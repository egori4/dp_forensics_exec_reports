# Chart Configuration Guide

## Overview
The DefensePro Forensics Analyzer supports comprehensive chart customization through an intuitive configuration system. You can easily customize:
- Chart types (line, bar, pie, donut, heatmap, area, etc.)
- Color themes with 6 professionally designed palettes
- Individual chart color overrides
- Chart styling preferences and layouts
- All visualizations across 11 different chart types

## Key Features
- **6 Professional Color Palettes**: Radware Corporate, Professional Blue, Modern Minimal, Vibrant Corporate, High Contrast, Colorblind Friendly
- **One-Click Theme Switching**: Change entire report color scheme instantly
- **Flexible Chart Types**: Multiple visualization options for each chart
- **Granular Color Control**: Override colors for specific charts while keeping global theme
- **Modern Architecture**: Clean separation of configuration and logic
- **Instant Updates**: Changes take effect on next report generation
- **Complete Coverage**: All 11 chart types fully configurable

## Quick Start
1. Open `config.py` in your text editor
2. Find the `COLOR_PALETTES` section to see available themes
3. Change `ACTIVE_COLOR_PALETTE = 'radware_corporate'` to your preferred theme
4. Modify chart types in `CHART_PREFERENCES` (e.g., change 'bar' to 'line')
5. Uncomment and customize specific colors in `CHART_COLOR_ASSIGNMENTS` if desired
6. Save and run `python analyzer.py` normally

## Configuration Options

### Global Color Themes
Choose from 6 professionally designed color palettes:
- **radware_corporate**: Official Radware branding colors (default)
- **professional_blue**: Corporate blue color scheme
- **modern_minimal**: Clean, modern grayscale with accents
- **vibrant_corporate**: Bright, engaging business colors
- **high_contrast**: Accessibility-optimized high contrast
- **colorblind_friendly**: Scientifically designed for color vision deficiency

### Chart Type Configuration
Each chart supports multiple visualization types:
- **Line Charts**: Trend analysis with optional markers and fill
- **Bar Charts**: Comparative data with vertical or horizontal orientation
- **Pie/Donut Charts**: Distribution analysis with customizable hole size
- **Area Charts**: Trend visualization with filled regions
- **Heatmaps**: Multi-dimensional data with color intensity
- **Stacked Charts**: Multi-category comparisons over time

### Individual Chart Overrides
Override specific chart colors while maintaining global theme:
- Monthly trends, attack distributions, volume analysis
- Protocol breakdown, source IP rankings, timeline views
- Policy analysis, bandwidth metrics, packet statistics

## Detailed Configuration Reference

### Available Chart Types by Visualization

Each chart in the report can be configured with specific visualization types and parameters:

#### 1. Monthly Events Trend
**Chart Types:** `line`, `bar`, `area`

**Line Configuration:**
- `mode`: Display style - `'lines+markers'`, `'lines'`, or `'markers'`
- `line_width`: Line thickness (1-10, default: 3)
- `marker_size`: Data point size (1-20, default: 8)
- `show_trend`: Display trend line overlay (true/false)

**Bar Configuration:**
- `show_values`: Display values on top of bars (true/false)
- `bar_width`: Bar width (0.1-1.0, default: 0.6)
- `values_text_size`: Font size for bar values (default: 12)
- `show_trend`: Display trend line overlay (true/false)

**Area Configuration:**
- `fill`: Fill mode - `'tonexty'` or `'tozeroy'`
- `line_width`: Border line thickness (default: 2)
- `show_trend`: Display trend line overlay (true/false)

#### 2. Attack Types Monthly (Stacked Visualization)
**Chart Types:** `stacked_bar`, `stacked_area`, `line`

**Configuration:**
- `top_n`: Number of top attack types to display (default: 5)

**Stacked Bar:**
- `bar_width`: Width of bars (0.1-1.0, default: 0.8)
- `show_values`: Display values on bars (true/false)
- `values_text_size`: Font size for values (default: 12)

**Stacked Area:**
- `line_width`: Border thickness (default: 2)
- `fill`: Fill mode - `'tonexty'` (stacked) or `'tozeroy'` (independent)
- `opacity`: Transparency level (0.0-1.0, default: 0.7)

**Line (Individual Trends):**
- `mode`: `'lines+markers'`, `'lines'`, or `'markers'`
- `line_width`: Line thickness (default: 2)
- `marker_size`: Data point size (default: 6)

**Best Practices:**
- Use `stacked_bar` for monthly comparisons and executive reports
- Use `stacked_area` for trend analysis and presentations
- Use `line` for detailed analysis with 3-5 attack types

#### 3. Attack Volume Trends (4 Subplots)
**Chart Types:** `line`, `bar`

**Line Configuration:**
- `mode`: `'lines+markers'`, `'lines'`, or `'markers'`
- `line_width`: Line thickness (default: 2)
- `marker_size`: Data point size (default: 6)
- `show_trend`: Display trend lines on subplots (true/false)

**Bar Configuration:**
- `bar_width`: Bar width (default: 0.7)
- `show_values`: Display values on bars (true/false)
- `values_text_size`: Font size for values (default: 12)
- `show_trend`: Display trend lines on subplots (true/false)

#### 4. Distribution Charts (Attack Type & Policy)
**Chart Types:** `pie`, `donut`, `bar`, `horizontal_bar`

**Pie Configuration:**
- `hole`: Donut hole size (0.0 = full pie, 0.4 = donut, up to 0.9)
- `textinfo`: Label content - `'label+percent'`, `'percent'`, `'label'`, `'value'`, `'label+value'`
- `textposition`: Label placement - `'outside'`, `'inside'`, `'auto'`

**Donut Configuration:**
- `hole`: Donut hole size (default: 0.4)
- `textinfo`: Label content options (as above)
- `textposition`: Label placement (as above)

**Bar Configuration:**
- `show_values`: Display values on bars (true/false)
- `sort_values`: Sort order - `'descending'` or `'ascending'`
- `values_text_size`: Font size for values (default: 12)

#### 5. Ranking Charts (Source IPs, Protocols, Top Attacks)
**Chart Types:** `bar`, `horizontal_bar`

**Configuration (both types):**
- `show_values`: Display values on/beside bars (true/false)
- `sort_values`: Sort order - `'descending'` or `'ascending'`
- `values_text_size`: Font size for values (default: 12)

**Note:** Horizontal bars automatically display with highest values at the top for better readability.

#### 6. Daily Timeline
**Chart Types:** `line`, `area`

**Line Configuration:**
- `mode`: `'lines+markers'`, `'lines'`, or `'markers'`
- `line_width`: Line thickness (default: 2)
- `marker_size`: Data point size (default: 4)

**Area Configuration:**
- `line_width`: Border line thickness (default: 2)
- `marker_size`: Data point size (default: 4)
- `mode`: Display mode (default: `'lines+markers'`)

#### 7. Hourly Heatmap
**Chart Type:** `heatmap` (fixed type)

**Configuration:**
Colors are controlled through `CHART_COLOR_ASSIGNMENTS`:
```python
'hourly_heatmap_colors': {
    'colorscale': 'Blues'  # Options: 'Blues', 'Reds', 'Viridis', 'Plasma', 'YlOrRd', 'RdYlGn_r'
}
```

### Configuration Examples

#### Example 1: Customize Monthly Trends as Thick Line Chart
```python
'monthly_events_trend': {
    'default_type': 'line',
    'line': {
        'mode': 'lines+markers',
        'line_width': 5,        # Thick line
        'marker_size': 12,      # Large markers
        'show_trend': True
    }
}
```

#### Example 2: Show Attack Types as Stacked Area with More Types
```python
'attack_types_monthly': {
    'default_type': 'stacked_area',
    'top_n': 10,  # Show top 10 instead of 5
    'stacked_area': {
        'line_width': 2,
        'fill': 'tonexty',
        'opacity': 0.8  # More opaque for presentations
    }
}
```

#### Example 3: Convert Pie Charts to Donuts
```python
'attack_type_distribution': {
    'default_type': 'pie',
    'pie': {
        'hole': 0.5,  # 50% donut hole
        'textinfo': 'label+percent',
        'textposition': 'outside'
    }
}
```

#### Example 4: Use Horizontal Bars with Values Displayed
```python
'top_source_ips': {
    'default_type': 'horizontal_bar',
    'horizontal_bar': {
        'show_values': True,
        'values_text_size': 14,  # Larger font
        'sort_values': 'descending'
    }
}
```

## Key Configuration Files
- **COLOR_PALETTES**: 6 predefined professional color schemes
- **ACTIVE_COLOR_PALETTE**: Global theme selection
- **CHART_PREFERENCES**: Chart type and behavior configuration
- **CHART_COLOR_ASSIGNMENTS**: Individual chart color overrides

## Configuration Architecture

The `config.py` file is organized into logical sections for ease of use:

### 1. Core Settings (Most Frequently Modified)
- **Output Format Control**: HTML/PDF generation options
- **Color Theme Selection**: One-click theme switching across all charts
- **Display Units**: Volume (MB/GB/TB) and packet (M/B) unit preferences
- **Data Filtering**: Exclude specific categories or attack types

### 2. Data Processing Configuration
- **Performance Optimization**: Memory usage and chunk size settings
- **CSV Column Mapping**: Expected and required column definitions
- **Date Format Handling**: Automatic detection with manual override options

### 3. Visualization Configuration
- **Color Palettes**: 6 professionally designed color schemes
- **Chart Type Preferences**: Default visualization types for each chart
- **Individual Chart Overrides**: Granular color and style customization
- **Layout and Styling**: Professional appearance controls

### 4. Advanced Settings
- **Unit Configuration Systems**: Detailed volume, packet, and bandwidth definitions
- **Chart Rendering Options**: Plotly configuration and optimization
- **Report Styling**: CSS and HTML template customization

## Benefits

### Ease of Use
- **Intuitive Organization**: Most important settings are prominently placed
- **Logical Grouping**: Related configurations are co-located
- **Clear Documentation**: Every setting includes purpose and usage examples
- **Progressive Complexity**: Basic to advanced settings flow naturally

### Customization Power
- **Theme System**: Professional color schemes for different use cases
- **Granular Control**: Override specific elements while maintaining global consistency
- **Chart Flexibility**: Multiple visualization types for each data analysis
- **Performance Tuning**: Optimize processing for different hardware configurations

### Professional Features
- **Corporate Branding**: Radware-specific defaults with full customization options
- **Accessibility Support**: Colorblind-friendly and high-contrast themes
- **Multi-Format Output**: Consistent styling across HTML and PDF formats