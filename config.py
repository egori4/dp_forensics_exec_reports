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

# Output format configuration
# DEFAULT OUTPUT FORMATS - controls what formats are generated when no specific format is requested
# This setting is used when:
#   - Running `python analyzer.py` (default behavior)
#   - Running `python analyzer.py --format both` (uses config setting)
# Command-line overrides still work:
#   - `python analyzer.py --format html` (HTML only, ignores config)
#   - `python analyzer.py --format pdf` (PDF only, ignores config)
OUTPUT_FORMATS = ['html']  # Available options: 'html', 'pdf'. Use ['html'] for HTML only, ['pdf'] for PDF only, or ['html', 'pdf'] for both

# Data filtering options
# Dynamic filters - exclude rows where column equals any of the specified values
# Multiple filters use AND logic (row must match ALL conditions to be excluded)
EXCLUDE_FILTERS = {
    # 'Threat Category': ['Anomalies'],  # Exclude Packet Anomalies and OOS detection records from analysis
    # 'Policy Name': ['Packet Anomalies'],  # Example: exclude Packet Anomalies only
    # 'Attack Name': ['DNS RFC-compliance violation'],  # Example: exclude specific attacks
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
    '%d.%m.%Y %H:%M:%S',  # DD.MM.YYYY HH:MM:SS (preferred for European format)
    '%m.%d.%Y %H:%M:%S',  # MM.DD.YYYY HH:MM:SS (example format)
]

# Force a specific date format (overrides auto-detection)
# Set to None for auto-detection, or specify exact format string
# Use this when you know the exact format and auto-detection fails
# Example: FORCE_DATE_FORMAT = '%d.%m.%Y %H:%M:%S'
FORCE_DATE_FORMAT = None  # Set to specific format string to override auto-detection or None for auto-detection


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

# Chart size optimization configuration
# Options for include_plotlyjs:
# - 'inline': Embed full Plotly library in each chart (largest files ~37MB, works offline)
# - 'cdn': Use Plotly CDN (smaller files ~116KB, requires internet)  
# - 'directory': Use local Plotly file (medium size, works offline if file available)
# - False: Only chart div, no Plotly library (smallest, requires manual Plotly inclusion)
CHART_PLOTLYJS_MODE = 'cdn'  # Options: 'inline', 'cdn', 'directory', False

# Log configuration
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

# Volume unit configuration
VOLUME_UNIT = 'GB'  # Options: 'MB', 'GB', 'TB'
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

# Bandwidth unit configuration (tied to VOLUME_UNIT)
# If VOLUME_UNIT is MB -> show Mbps, if GB -> show Gbps, if TB -> show Gbps
BANDWIDTH_UNIT_CONFIGS = {
    'MB': {
        'divider': 1_000_000,       # bps to Mbps: divide by 1,000,000
        'unit_name': 'Mbps',
        'chart_title': 'Attack Max Mbps',
        'stats_label': 'Attack Max Mbps',
        'chart_name': 'Max Mbps',
        'hover_template': '<b>%{x}</b><br>Max Mbps: %{y:,.2f}<extra></extra>'
    },
    'GB': {
        'divider': 1_000_000_000,   # bps to Gbps: divide by 1,000,000,000
        'unit_name': 'Gbps',
        'chart_title': 'Attack Max Gbps',
        'stats_label': 'Attack Max Gbps',
        'chart_name': 'Max Gbps',
        'hover_template': '<b>%{x}</b><br>Max Gbps: %{y:,.2f}<extra></extra>'
    },
    'TB': {
        'divider': 1_000_000_000,   # bps to Gbps: divide by 1,000,000,000 (keep as Gbps for TB)
        'unit_name': 'Gbps',
        'chart_title': 'Attack Max Gbps',
        'stats_label': 'Attack Max Gbps',
        'chart_name': 'Max Gbps',
        'hover_template': '<b>%{x}</b><br>Max Gbps: %{y:,.2f}<extra></extra>'
    }
}

# Helper function to get current bandwidth unit config
def get_bandwidth_unit_config():
    return BANDWIDTH_UNIT_CONFIGS.get(VOLUME_UNIT, BANDWIDTH_UNIT_CONFIGS['GB'])

# Packet unit configuration
PACKET_UNIT = 'M'  # Options: 'M' (millions), 'B' (billions), '' (no conversion)
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

# Chart type and styling configuration
CHART_PREFERENCES = {
    'monthly_events_trend': {
        'type': 'bar',  # Options: 'line', 'bar'
        'colors': {
            'primary': '#003f7f',      # Main color for data
            'hover': '#002d5a',        # Hover color
        }
    },
    'attack_volume_trends': {
        'type': 'bar',  # Options: 'line', 'bar'
        'colors': {
            'volume': '#003f7f',       # Total Volume color
            'packets': '#6cb2eb',      # Total Packets color
            'pps': '#ff6b35',          # Max PPS color
            'bandwidth': '#28a745',    # Max Bandwidth color
        }
    },

    'hourly_heatmap': {
        'colorscale': 'Blues',  # Options: 'Blues', 'Reds', 'Viridis', 'Plasma', etc. - Attack Intensity by Hour heatmap
        'colors': {
            'text': '#ffffff',
            'background': '#f8f9fa',
        }
    }
}

# Available chart types for each visualization
AVAILABLE_CHART_TYPES = {
    'monthly_events_trend': ['line', 'bar'],           # Security Events Per Month
    'attack_volume_trends': ['line', 'bar'],           # Attack Volume Trends Over Time (4 subplots)
    'hourly_heatmap': ['heatmap'],                     # Attack Intensity by Hour heatmap
}




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
        word-break: break-word;
        line-height: 1.2;
    }
    
    /* Dynamic font sizing classes for long stat values */
    .stat-value.long-stat {
        font-size: 1.6em;
    }
    
    .stat-value.very-long-stat {
        font-size: 1.3em;
    }
    
    .stat-value.extremely-long-stat {
        font-size: 1.1em;
        line-height: 1.1;
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
    
    /* Expandable stat card styles */
    .expandable-card {
        position: relative;
    }
    
    .expandable-trigger {
        transition: background-color 0.2s ease;
    }
    
    .expandable-trigger:hover {
        background-color: rgba(0, 63, 127, 0.05);
        border-radius: 4px;
    }
    
    .expand-icon {
        position: absolute;
        right: 10px;
        top: 50%;
        transform: translateY(-50%);
        font-size: 12px;
        color: #6c757d;
        transition: transform 0.3s ease;
    }
    
    .expand-icon.rotated {
        transform: translateY(-50%) rotate(180deg);
    }
    
    .attack-details {
        margin-top: 15px;
        padding: 0;
        max-height: 0;
        overflow: hidden;
        transition: max-height 0.3s ease-out, padding 0.3s ease-out;
    }
    
    .attack-details.expanded {
        max-height: 500px;
        padding: 15px 0;
        overflow-y: auto;
    }
    
    .details-container {
        background: #f8f9fa;
        border: 1px solid #dee2e6;
        border-radius: 6px;
        padding: 15px;
        font-size: 13px;
    }
    
    .detail-row {
        margin-bottom: 12px;
        padding: 8px 0;
        border-bottom: 1px solid #f1f3f4;
    }
    
    .detail-row:last-child {
        margin-bottom: 0;
        border-bottom: none;
        padding-bottom: 0;
    }
    
    .detail-label {
        font-weight: 600;
        color: #495057;
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-bottom: 4px;
        display: block;
    }
    
    .detail-value {
        color: #003f7f;
        font-size: 14px;
        font-weight: 500;
        display: block;
        margin-left: 0;
        background-color: #f8f9fa;
        padding: 6px 10px;
        border-radius: 4px;
        border-left: 3px solid #003f7f;
        word-break: break-word;
    }
    
    /* Mobile responsiveness for expandable cards */
    @media (max-width: 768px) {
        .detail-value {
            font-size: 13px;
            padding: 5px 8px;
        }
        
        .detail-label {
            font-size: 11px;
        }
        
        .expand-icon {
            right: 5px;
        }
    }
</style>

<script>
function toggleDetails(detailsId) {
    const detailsElement = document.getElementById(detailsId);
    const iconElement = document.getElementById(detailsId + '-icon');
    
    if (detailsElement.classList.contains('expanded')) {
        // Collapse
        detailsElement.classList.remove('expanded');
        iconElement.classList.remove('rotated');
    } else {
        // Expand
        detailsElement.classList.add('expanded');
        iconElement.classList.add('rotated');
        
        // Apply dynamic font sizing after expansion
        setTimeout(() => {
            adjustStatValueFontSizes();
        }, 100);
    }
}

function adjustStatValueFontSizes() {
    // Adjust stat values (main stat numbers)
    const statValues = document.querySelectorAll('.stat-value');
    
    statValues.forEach(element => {
        // Reset classes
        element.classList.remove('long-stat', 'very-long-stat', 'extremely-long-stat');
        
        const text = element.textContent || element.innerText;
        // Remove icon text from measurement
        const cleanText = text.replace('▼', '').trim();
        const textLength = cleanText.length;
        
        // Apply classes based on text length for stat values
        if (textLength > 18) {
            element.classList.add('extremely-long-stat');
        } else if (textLength > 16) {
            element.classList.add('very-long-stat');
        } else if (textLength > 10) {
            element.classList.add('long-stat');
        }
        
        // Additional overflow detection for stat values
        setTimeout(() => {
            let attempts = 0;
            while (element.scrollWidth > element.clientWidth && attempts < 3) {
                if (element.classList.contains('extremely-long-stat')) {
                    // Already at smallest size
                    break;
                } else if (element.classList.contains('very-long-stat')) {
                    element.classList.remove('very-long-stat');
                    element.classList.add('extremely-long-stat');
                } else if (element.classList.contains('long-stat')) {
                    element.classList.remove('long-stat');
                    element.classList.add('very-long-stat');
                } else {
                    element.classList.add('long-stat');
                }
                attempts++;
            }
        }, 50);
    });
}

// Apply font sizing on page load
document.addEventListener('DOMContentLoaded', function() {
    adjustStatValueFontSizes();
});
</script>
"""


