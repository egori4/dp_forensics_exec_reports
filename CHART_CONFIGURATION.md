# Chart Configuration Guide

## Overview
The DefensePro Forensics Analyzer supports fully configurable chart types and colors. You can customize:
- Chart types (line vs bar charts)
- Colors for each chart element  
- Chart styling preferences
- Heatmap colorscales

## Features Added
- **Configurable chart types**: Switch between line and bar charts for trend visualizations
- **Custom color schemes**: Define colors for each chart element (volume, packets, PPS, bandwidth)
- **Multiple chart support**: Configure 5 different chart types independently
- **Hot configuration**: Changes in config.py take effect immediately on next run
- **Validation system**: Built-in validation prevents invalid chart types/colors
- **Helper methods**: Programmatic access for advanced customization
- **Comprehensive examples**: Ready-to-use configuration templates

## Quick Start
1. Open `config.py` in your text editor
2. Find the `CHART_PREFERENCES` section (around line 230)
3. Change `'type': 'bar'` to `'type': 'line'` for line charts
4. Change colors by modifying hex values like `'primary': '#ff6b35'` (orange)
5. Save the file and run `python analyzer.py` normally

## Configuration Methods

### Configuration File (Recommended)
Edit the `CHART_PREFERENCES` section in `config.py`:

```python
CHART_PREFERENCES = {
    'monthly_events_trend': {
        'type': 'line',  # or 'bar'
        'colors': {
            'primary': '#ff6b35',  # Orange instead of blue
        }
    },
    'attack_volume_trends': {
        'type': 'line',  # or 'bar'
        'colors': {
            'volume': '#dc3545',     # Red for volume
            'packets': '#28a745',    # Green for packets
            'pps': '#ffc107',        # Yellow for PPS
            'bandwidth': '#6f42c1',  # Purple for bandwidth
        }
    }
}
```

### Programmatic Configuration (Advanced)
For advanced users or automation scripts:

```python
from visualizations import ForensicsVisualizer

viz = ForensicsVisualizer()

# Change monthly events to line chart with orange color
viz.update_chart_preferences('monthly_events_trend', {
    'type': 'line',
    'colors': {'primary': '#ff6b35'}
})

# Change volume trends to bar charts with custom colors
viz.update_chart_preferences('attack_volume_trends', {
    'type': 'bar',
    'colors': {
        'volume': '#dc3545',
        'packets': '#28a745', 
        'pps': '#ffc107',
        'bandwidth': '#6f42c1'
    }
})
```

## Available Chart Types

### Monthly Events Trend
- **line**: Line chart with markers (good for showing trends over time)
- **bar**: Bar chart (good for comparing discrete values)

### Attack Volume Trends (4 subplots)
- **line**: Line charts with markers (emphasizes trends and patterns)
- **bar**: Bar charts (better for comparing monthly totals)

### Attack Intensity by Hour Heatmap
- **heatmap**: Only one type available
- Configurable colorscale: 'Blues', 'Reds', 'Viridis', 'Plasma', 'Cividis', etc.

## Color Configuration

### Color Keys by Chart Type

#### Monthly Events Trend
- `primary`: Main data color
- `hover`: Hover state color (for line charts)

#### Attack Volume Trends  
- `volume`: Total volume color
- `packets`: Total packets color
- `pps`: Max PPS color
- `bandwidth`: Max bandwidth color

#### Attack Intensity by Hour Heatmap
- `colorscale`: Color scheme for the heatmap ('Blues', 'Reds', 'Viridis', etc.)
- `text`: Text color (not currently used)
- `background`: Background color (not currently used)

### Color Formats
All CSS color formats are supported:
- Hex: `#ff6b35`, `#003f7f`
- RGB: `rgb(255, 107, 53)`
- RGBA: `rgba(255, 107, 53, 0.8)`
- Named: `red`, `blue`, `orange`

### Predefined Color Palette
```python
RADWARE_COLORS = {
    'primary': '#003f7f',      # Radware blue
    'secondary': '#6cb2eb',    # Light blue
    'accent': '#ff6b35',       # Orange accent
    'success': '#28a745',      # Green
    'warning': '#ffc107',      # Yellow
    'danger': '#dc3545',       # Red
    'dark': '#343a40',         # Dark gray
    'light': '#f8f9fa',        # Light gray
}
```

## Example Configurations

### Professional Blue Theme (Default)
```python
'monthly_events_trend': {
    'type': 'bar',
    'colors': {'primary': '#003f7f'}
},
'attack_volume_trends': {
    'type': 'bar',
    'colors': {
        'volume': '#003f7f',
        'packets': '#6cb2eb', 
        'pps': '#ff6b35',
        'bandwidth': '#28a745'
    }
}
```

### High Contrast Theme
```python
'monthly_events_trend': {
    'type': 'line',
    'colors': {'primary': '#dc3545'}  # Red
},
'attack_volume_trends': {
    'type': 'line', 
    'colors': {
        'volume': '#dc3545',      # Red
        'packets': '#28a745',     # Green
        'pps': '#ffc107',         # Yellow
        'bandwidth': '#6f42c1'    # Purple
    }
}
```

### Colorblind-Friendly Theme
```python
'monthly_events_trend': {
    'type': 'bar',
    'colors': {'primary': '#0173b2'}  # Blue
},
'attack_volume_trends': {
    'type': 'bar',
    'colors': {
        'volume': '#0173b2',      # Blue
        'packets': '#029e73',     # Green  
        'pps': '#d55e00',         # Orange
        'bandwidth': '#cc78bc'    # Pink
    }
}
```

## Best Practices

### When to Use Line vs Bar Charts

**Line Charts** are better for:
- Showing trends and patterns over time
- Emphasizing continuity and change rates
- When you have many data points
- Highlighting the relationship between consecutive periods

**Bar Charts** are better for:
- Comparing discrete values
- When exact values matter more than trends
- Emphasizing magnitude differences
- When you have fewer data points

### Color Selection Tips

1. **Contrast**: Ensure sufficient contrast for readability
2. **Consistency**: Use similar color schemes across related charts
3. **Accessibility**: Consider colorblind-friendly palettes
4. **Branding**: Match your organization's color scheme
5. **Purpose**: Use red for alerts/high values, green for normal/good values

### Performance Considerations

- Color changes have no performance impact
- Chart type changes have minimal performance impact
- Line charts may render slightly faster for large datasets
- Bar charts may be clearer for small datasets

## Troubleshooting

### Common Issues

1. **Invalid chart type**: Check available types in the `AVAILABLE_CHART_TYPES` section of `config.py`
2. **Color not applied**: Verify the color key matches the chart type
3. **Syntax errors**: Ensure proper Python syntax in config.py (commas, quotes, brackets)
4. **Changes not visible**: Restart the analyzer after making config.py changes


## Support

### Chart Configuration Summary

**Configurable Charts:**
- **`monthly_events_trend`** → "Security Events Per Month" (line or bar chart)
- **`attack_volume_trends`** → "Attack Volume Trends Over Time" (4 subplots: line or bar)
- **`hourly_heatmap`** → "Attack Intensity by Hour" heatmap (colorscale options)

**Non-Configurable Charts:**
- **"Top 5 Attack Types Per Month"** → Always uses stacked bar chart with preset colors
- **All other charts** → Use default styling and cannot be customized

### Files Modified for Chart Configuration
- **config.py**: Added `CHART_PREFERENCES` and `AVAILABLE_CHART_TYPES` sections
- **visualizations.py**: Enhanced with configurable chart creation methods
- **analyzer.py**: Updated help text to reference config.py approach


### Key Methods Added
- `_create_trace_by_type()`: Creates charts based on configuration
- `_get_chart_type()`: Retrieves configured chart type
- `update_chart_preferences()`: Programmatically update preferences
- `get_chart_preferences()`: View current configuration
- `reset_chart_preferences()`: Reset to defaults

For additional customization needs or questions:

1. Review available colorscales for heatmaps in config.py
2. Modify the `CHART_PREFERENCES` in `config.py` for persistent changes