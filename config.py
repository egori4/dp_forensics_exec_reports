"""
Configuration constants for the Forensics Data Analysis & Report Generator
"""

# Chart styling constants for Radware branding
RADWARE_COLORS = {
    'primary': '#003f7f',      # Radware blue
    'secondary': '#6cb2eb',    # Light blue
    'accent': '#ff6b35',       # Orange accent
    'success': '#28a745',      # Green
    'warning': '#ffc107',      # Yellow
    'danger': '#dc3545',       # Red
    'dark': '#343a40',         # Dark gray
    'light': '#f8f9fa',        # Light gray
    'background': '#ffffff',    # White background
}

# Color palette for charts (colorblind friendly)
CHART_COLORS = [
    '#003f7f', '#6cb2eb', '#ff6b35', '#28a745', '#ffc107',
    '#dc3545', '#17a2b8', '#6f42c1', '#e83e8c', '#fd7e14',
    '#20c997', '#6610f2', '#e91e63', '#795548', '#607d8b'
]

# Data processing constants
CHUNK_SIZE = 50000  # Number of rows to process at once
MAX_MEMORY_USAGE_GB = 2  # Maximum memory usage in GB before warning

# Data filtering options
# Dynamic filters - exclude rows where column equals any of the specified values
# Multiple filters use AND logic (row must match ALL conditions to be excluded)
EXCLUDE_FILTERS = {
    # 'Threat Category': ['Anomalies'],  # Exclude anomaly detection records from analysis
    'Policy Name': ['Packet Anomalies'],  # Example: exclude specific policies
    # 'Attack Name': ['Health Check', 'Benign Traffic'],  # Example: exclude specific attacks
    # 'Risk': ['Low'],  # Example: exclude low-risk events
    # 'Direction': ['Internal'],  # Example: exclude internal traffic
}

# Expected CSV columns (some may be missing depending on device)
EXPECTED_COLUMNS = [
    'S.No', 'Start Time', 'End Time', 'Device IP Address', 'Threat Category',
    'Attack Name', 'Policy Name', 'Action', 'Attack ID', 'Source IP Address',
    'Source Port', 'Destination IP Address', 'Destination Port', 'Direction',
    'Protocol', 'Radware ID', 'Duration', 'Total Packets', 'Packet Type',
    'Total Mbits', 'Max pps', 'Max bps', 'Physical Port', 'Risk', 'VLAN Tag',
    'Footprint', 'Device Name', 'Device Type', 'Workflow Rule Process',
    'Activation Id', 'Protected Object'
]

# Required columns for basic functionality
REQUIRED_COLUMNS = [
    'Start Time', 'Attack Name', 'Source IP Address', 'Destination IP Address'
]

# Date formats to try (in order of preference)
DATE_FORMATS = [
    '%m.%d.%Y %H:%M:%S',  # MM.DD.YYYY HH:MM:SS (example format)
    '%d.%m.%Y %H:%M:%S',  # DD.MM.YYYY HH:MM:SS
    '%Y-%m-%d %H:%M:%S',  # YYYY-MM-DD HH:MM:SS
    '%m/%d/%Y %H:%M:%S',  # MM/DD/YYYY HH:MM:SS
    '%d/%m/%Y %H:%M:%S',  # DD/MM/YYYY HH:MM:SS
    '%Y/%m/%d %H:%M:%S',  # YYYY/MM/DD HH:MM:SS
    '%m-%d-%Y %H:%M:%S',  # MM-DD-YYYY HH:MM:SS
    '%d-%m-%Y %H:%M:%S',  # DD-MM-YYYY HH:MM:SS
]

# Report styling
REPORT_CSS = """
<style>
    body {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        margin: 0;
        padding: 20px;
        background-color: #f8f9fa;
        color: #333;
        line-height: 1.6;
    }
    
    .container {
        max-width: 1200px;
        margin: 0 auto;
        background-color: white;
        box-shadow: 0 0 20px rgba(0,0,0,0.1);
        border-radius: 8px;
        overflow: hidden;
    }
    
    .header {
        background: linear-gradient(135deg, #003f7f 0%, #6cb2eb 100%);
        color: white;
        padding: 30px;
        text-align: center;
    }
    
    .header h1 {
        margin: 0;
        font-size: 2.5em;
        font-weight: 300;
    }
    
    .header p {
        margin: 10px 0 0 0;
        font-size: 1.2em;
        opacity: 0.9;
    }
    
    .content {
        padding: 30px;
    }
    
    .section {
        margin-bottom: 40px;
        border-bottom: 1px solid #e9ecef;
        padding-bottom: 30px;
    }
    
    .section:last-child {
        border-bottom: none;
    }
    
    .section h2 {
        color: #003f7f;
        border-left: 4px solid #ff6b35;
        padding-left: 15px;
        margin-bottom: 20px;
        font-size: 1.8em;
    }
    
    .section h3 {
        color: #495057;
        margin-top: 30px;
        margin-bottom: 15px;
    }
    
    .stats-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
        gap: 20px;
        margin-bottom: 30px;
    }
    
    .stat-card {
        background: #f8f9fa;
        border: 1px solid #dee2e6;
        border-radius: 8px;
        padding: 20px;
        text-align: center;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    
    .stat-value {
        font-size: 2em;
        font-weight: bold;
        color: #003f7f;
        margin-bottom: 5px;
    }
    
    .stat-label {
        color: #6c757d;
        font-size: 0.9em;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    
    .chart-container {
        margin: 20px 0;
        padding: 15px;
        background: white;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    
    .warning {
        background: #fff3cd;
        border: 1px solid #ffeaa7;
        border-radius: 4px;
        padding: 15px;
        margin: 20px 0;
        color: #856404;
    }
    
    .info {
        background: #d1ecf1;
        border: 1px solid #bee5eb;
        border-radius: 4px;
        padding: 15px;
        margin: 20px 0;
        color: #0c5460;
    }
    
    .footer {
        background: #f8f9fa;
        border-top: 1px solid #dee2e6;
        padding: 20px 30px;
        text-align: center;
        color: #6c757d;
        font-size: 0.9em;
    }
    
    table {
        width: 100%;
        border-collapse: collapse;
        margin: 20px 0;
        background: white;
        border-radius: 8px;
        overflow: hidden;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    
    th, td {
        padding: 12px 15px;
        text-align: left;
        border-bottom: 1px solid #dee2e6;
    }
    
    th {
        background: #003f7f;
        color: white;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        font-size: 0.9em;
    }
    
    tr:hover {
        background: #f8f9fa;
    }
    
    .progress-bar {
        background: #e9ecef;
        border-radius: 4px;
        overflow: hidden;
        height: 20px;
        margin: 10px 0;
    }
    
    .progress {
        background: linear-gradient(90deg, #003f7f, #6cb2eb);
        height: 100%;
        transition: width 0.3s ease;
    }
    
    @media (max-width: 768px) {
        .container {
            margin: 10px;
            border-radius: 0;
        }
        
        .header {
            padding: 20px;
        }
        
        .header h1 {
            font-size: 2em;
        }
        
        .content {
            padding: 20px;
        }
        
        .stats-grid {
            grid-template-columns: 1fr;
        }
    }
</style>
"""

# Chart configuration
CHART_CONFIG = {
    'displayModeBar': False,
    'responsive': True
}

CHART_LAYOUT = {
    'font': {'family': 'Segoe UI, Tahoma, Geneva, Verdana, sans-serif'},
    'plot_bgcolor': 'white',
    'paper_bgcolor': 'white',
    'margin': {'l': 60, 'r': 60, 't': 80, 'b': 80},
    'showlegend': True,
    'legend': {
        'orientation': 'h',
        'yanchor': 'bottom',
        'y': -0.2,
        'xanchor': 'center',
        'x': 0.5
    }
}

# Log configuration
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

# Performance thresholds
PERFORMANCE_THRESHOLDS = {
    'small_file_mb': 10,      # Files under 10MB
    'medium_file_mb': 100,    # Files 10-100MB  
    'large_file_mb': 500,     # Files 100-500MB
    'max_rows_warning': 1000000,  # Warn if over 1M rows
}

# Volume unit configuration
VOLUME_UNIT = 'MB'  # Options: 'MB', 'GB', 'TB'
VOLUME_UNIT_CONFIGS = {
    'MB': {
        'divider': 1,           # Mbits to MB: divide by 1 (already in Mbits, then divide by 8 for bytes)
        'display_name': 'MB',
        'chart_title': 'Aggregate Attack Volume (MB)',
        'stats_label': 'Aggregate Attack Volume (MB)'
    },
    'GB': {
        'divider': 1000,        # Mbits to GB: divide by 1000, then by 8 for bytes
        'display_name': 'GB', 
        'chart_title': 'Aggregate Attack Volume (GB)',
        'stats_label': 'Aggregate Attack Volume (GB)'
    },
    'TB': {
        'divider': 1000000,     # Mbits to TB: divide by 1,000,000, then by 8 for bytes
        'display_name': 'TB',
        'chart_title': 'Aggregate Attack Volume (TB)', 
        'stats_label': 'Aggregate Attack Volume (TB)'
    }
}

# Packet unit configuration
PACKET_UNIT = ''  # Options: 'M' (millions), 'B' (billions), '' (no conversion)
PACKET_UNIT_CONFIGS = {
    'M': {
        'divider': 1_000_000,   # Convert to millions
        'display_name': 'M',
        'chart_title': 'Aggregate Attack Packets (Millions)',
        'stats_label': 'Aggregate Attack Packets (Millions)'
    },
    'B': {
        'divider': 1_000_000_000,  # Convert to billions
        'display_name': 'B',
        'chart_title': 'Aggregate Attack Packets (Billions)', 
        'stats_label': 'Aggregate Attack Packets (Billions)'
    },
    '': {
        'divider': 1,           # No conversion
        'display_name': '',
        'chart_title': 'Aggregate Attack Packets',
        'stats_label': 'Aggregate Attack Packets'
    }
}