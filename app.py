import streamlit as st
import pandas as pd
import plotly.express as px
import io

# Allowed Finding Sources (Dropdown Options)
FINDING_SOURCES = [
    "Application Security:Application Security - WAPT",
    "Web App Scanning Service",
    "Offensive Security",
    "Application Security",
    "Application Security:Application Security - DVST",
    "External Attack Surface Management (EASM)"
]

# Function to process uploaded Excel file
def analyze_excel_with_pivot(file, start_date=None, end_date=None, selected_sources=None):
    try:
        data = pd.read_excel(file)

        required_columns = [
            "Finding ID", "Finding Name", "Finding Status", "First Published",
            "Finding Owner", "Finding Source", "Finding Criticality", "Finding Curator Responsible",
            "Applications", "Finding Due/Overdue", "CVSS v3.0 Criticality", "Finding Closure Date", "Business Area"
        ]

        missing_columns = [col for col in required_columns if col not in data.columns]
        if missing_columns:
            st.error(f"Error: Missing required columns: {missing_columns}")
            return None

        # Clean Data
        data["Finding Status"] = data["Finding Status"].str.strip().str.lower()
        data["Finding Due/Overdue"] = data["Finding Due/Overdue"].str.strip().str.lower()

        # Status Mapping
        status_mapping = {
            "finding closed": "Finding Closed",
            "finding discarded": "Finding Closed",
            "fo documenting security policy exception": "Finding Open",
            "fo documenting high-level remediation plan(s)": "Finding Open",
            "fo reviewing finding": "Finding Open",
            "finding closed – security policy exception active": "Finding Closed",
            "fo analyzing treatment options": "Finding Open",
            "submitted to finding curator": "Finding Open"
        }
        
        data["Mapped Status"] = data["Finding Status"].map(status_mapping)
        data = data[data["Mapped Status"].notna()]

        # Ensure correct date parsing
        data["Finding Closure Date"] = pd.to_datetime(data["Finding Closure Date"], errors='coerce')
        data["First Published"] = pd.to_datetime(data["First Published"], format="%d/%m/%Y %H:%M", errors='coerce')

        # Apply Filters
        if start_date and end_date:
            start_date = pd.to_datetime(start_date)
            end_date = pd.to_datetime(end_date)
            data = data[(data["First Published"] >= start_date) & (data["First Published"] <= end_date)]

        if selected_sources:
            data = data[data["Finding Source"].isin(selected_sources)]

        # Create Pivot Tables
        total_vulnerable_apps_by_BA = data.groupby("Business Area")["Applications"].nunique()
        high_vuln_apps_by_BA = data[data["Finding Criticality"] == "High"].groupby("Business Area")["Applications"].nunique()

        closed_findings = data[data["Mapped Status"] == "Finding Closed"].pivot_table(
            index="Business Area", columns="Finding Criticality", values="Finding ID", aggfunc="count", fill_value=0
        )

        open_findings = data[data["Mapped Status"] == "Finding Open"].pivot_table(
            index="Business Area", columns="Finding Criticality", values="Finding ID", aggfunc="count", fill_value=0
        )

        overdue_findings = data[(data["Mapped Status"] == "Finding Open") & data["Finding Due/Overdue"].str.contains("overdue", na=False)].pivot_table(
            index="Business Area", columns="Finding Criticality", values="Finding ID", aggfunc="count", fill_value=0
        )

        criticality_by_area = data.pivot_table(
            index="Business Area", columns="Finding Criticality", values="Finding ID", aggfunc="count", fill_value=0
        )

        return data, total_vulnerable_apps_by_BA, high_vuln_apps_by_BA, closed_findings, open_findings, overdue_findings, criticality_by_area
    except Exception as e:
        st.error(f"An error occurred: {e}")
        return None


# Streamlit UI
st.set_page_config(page_title="Security Findings Dashboard", layout="wide")

st.sidebar.header("Upload Excel File")
uploaded_file = st.sidebar.file_uploader("Upload an Excel file", type=["xls", "xlsx"])

# Filters
start_date = st.sidebar.date_input("Start Date", None)
end_date = st.sidebar.date_input("End Date", None)
selected_sources = st.sidebar.multiselect("Finding Sources", FINDING_SOURCES)

# Process File
if uploaded_file:
    result = analyze_excel_with_pivot(uploaded_file, start_date, end_date, selected_sources)

    if result:
        data, total_vulnerable_apps_by_BA, high_vuln_apps_by_BA, closed_findings, open_findings, overdue_findings, criticality_by_area = result

        # Calculate KPIs
        total_findings = len(data)
        open_findings_count = len(data[data["Mapped Status"] == "Finding Open"])
        closed_findings_count = len(data[data["Mapped Status"] == "Finding Closed"])
        overdue_findings_count = len(data[(data["Mapped Status"] == "Finding Open") & 
                                          data["Finding Due/Overdue"].str.contains("overdue", na=False)])
        high_risk_findings = len(data[data["Finding Criticality"] == "High"])
        affected_apps = data["Applications"].nunique()

        # Display KPIs
        st.title("📊 Security Findings Dashboard")
        st.markdown("### Overview of Findings and Criticality by Business Area")
        col1, col2, col3 = st.columns(3)

        with col1:
            st.metric(label="🔍 Total Findings", value=total_findings)
            st.metric(label="⚠️ High-Risk Findings", value=high_risk_findings)

        with col2:
            st.metric(label="📂 Open Findings", value=open_findings_count)
            st.metric(label="❌ Closed Findings", value=closed_findings_count)

        with col3:
            st.metric(label="⏳ Overdue Findings", value=overdue_findings_count)
            st.metric(label="🛠️ Affected Applications", value=affected_apps)

        

        col1, col2 = st.columns(2)
        
        with col1:
            fig1 = px.bar(total_vulnerable_apps_by_BA, x=total_vulnerable_apps_by_BA.index, y=total_vulnerable_apps_by_BA.values,
                          labels={"y": "Total Vulnerable Apps", "x": "Business Area"}, title="Total Vulnerable Apps by Business Area",text_auto=True)
            st.plotly_chart(fig1, use_container_width=True)

        with col2:
            fig2 = px.bar(high_vuln_apps_by_BA, x=high_vuln_apps_by_BA.index, y=high_vuln_apps_by_BA.values,
                          labels={"y": "High Severity Apps", "x": "Business Area"}, title="High Vulnerability Apps by Business Area", color_discrete_sequence=["red", "orange", "yellow"],text_auto=True)
            st.plotly_chart(fig2, use_container_width=True)

        st.markdown("### Findings Status Distribution")

        col3, col4 = st.columns(2)

        with col3:
            fig3 = px.bar(closed_findings, barmode="stack", labels={"value": "Closed Findings Count", "Business Area": "Business Area"},
                          title="Closed Findings by Business Area",text_auto=True)
            st.plotly_chart(fig3, use_container_width=True)

        with col4:
            fig4 = px.bar(open_findings, barmode="stack", labels={"value": "Open Findings Count", "Business Area": "Business Area"},
                          title="Open Findings by Business Area", color_discrete_sequence=["red", "orange", "yellow"],text_auto=True)
            st.plotly_chart(fig4, use_container_width=True)

        st.markdown("### Overdue & Severity Distribution")

        col5, col6 = st.columns(2)

        with col5:
            fig5 = px.bar(overdue_findings, barmode="stack", labels={"value": "Overdue Findings Count", "Business Area": "Business Area"},
                          title="Overdue Findings by Business Area", color_discrete_sequence=["red", "orange", "yellow"],text_auto=True)
            st.plotly_chart(fig5, use_container_width=True)

        with col6:
            fig6 = px.bar(criticality_by_area, barmode="stack", labels={"value": "Severity Count", "Business Area": "Business Area"},
                          title="Severity Distribution by Business Area", color_discrete_sequence=["red", "orange", "yellow"],text_auto=True)
            st.plotly_chart(fig6, use_container_width=True)

        # Export Button
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
            data.to_excel(writer, sheet_name="Filtered Findings", index=False)
            total_vulnerable_apps_by_BA.to_excel(writer, sheet_name="Total Vulnerable Apps")
            high_vuln_apps_by_BA.to_excel(writer, sheet_name="High Vuln Apps")
            closed_findings.to_excel(writer, sheet_name="Closed Findings")
            open_findings.to_excel(writer, sheet_name="Open Findings")
            overdue_findings.to_excel(writer, sheet_name="Overdue Findings")
            criticality_by_area.to_excel(writer, sheet_name="Severity Distribution")

        output.seek(0)
        st.download_button(label="📥 Download Report", data=output, file_name="Processed_Report.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

