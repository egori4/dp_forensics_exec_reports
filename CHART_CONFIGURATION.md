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