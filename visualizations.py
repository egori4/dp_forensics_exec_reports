"""
Visualization module for creating interactive charts and graphs.

This module creates professional, interactive visualizations using Plotly
with Radware branding and styling for both technical and sales audiences.

EXPANDABLE STAT CARDS:
This module includes functionality for creating expandable stat cards that 
show detailed information when clicked. Use cases include:
- Longest Attack Duration (shows full attack details)
- Top Source IP (shows attack breakdown)
- Highest Volume Attack (shows attack characteristics)

To create custom expandable cards:
    custom_fields = [
        ('Field Name', 'Field Value'),
        ('Source IP', '192.168.1.100'),
        ('Volume (MB)', '1,250.5')
    ]
    html = visualizer.create_expandable_stat_card_for_custom_data(
        "Card Title", "Main Value", custom_fields, "unique-id"
    )
"""

import logging
from typing import Dict, List, Any, Optional, Tuple
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import pandas as pd
from datetime import datetime, timedelta

from config import (
    RADWARE_COLORS, CHART_COLORS, CHART_CONFIG, CHART_LAYOUT, 
    VOLUME_UNIT, VOLUME_UNIT_CONFIGS, PACKET_UNIT, PACKET_UNIT_CONFIGS,
    get_bandwidth_unit_config, CHART_PLOTLYJS_MODE, CHART_PREFERENCES,
    AVAILABLE_CHART_TYPES
)
from utils import format_number, calculate_percentage

logger = logging.getLogger(__name__)


class ForensicsVisualizer:
    """
    Creates interactive visualizations for forensics data analysis.
    """
    
    def __init__(self):
        """Initialize the visualizer with Radware styling."""
        self.colors = RADWARE_COLORS
        self.chart_colors = CHART_COLORS
        self.base_layout = CHART_LAYOUT.copy()
        self.chart_preferences = CHART_PREFERENCES
        self.available_types = AVAILABLE_CHART_TYPES
        
        logger.info("Initialized ForensicsVisualizer with Radware styling")
    
    def _convert_to_html(self, fig):
        """
        Convert Plotly figure to HTML with optimized Plotly inclusion.
        
        Args:
            fig: Plotly figure object
            
        Returns:
            HTML string of the chart
        """
        return fig.to_html(config=CHART_CONFIG, include_plotlyjs=CHART_PLOTLYJS_MODE)
    
    def _create_trace_by_type(self, chart_type: str, chart_name: str, x_data, y_data, 
                             color_key: str = 'primary', name: str = None, 
                             hovertemplate: str = None, **kwargs):
        """
        Create a trace based on chart type configuration.
        
        Args:
            chart_type: Type of chart ('line', 'bar', etc.)
            chart_name: Name of chart config in CHART_PREFERENCES
            x_data: X-axis data
            y_data: Y-axis data
            color_key: Key for color in chart preferences
            name: Trace name
            hovertemplate: Hover template
            **kwargs: Additional trace parameters
            
        Returns:
            Plotly trace object
        """
        # Get chart preferences
        chart_config = self.chart_preferences.get(chart_name, {})
        chart_colors = chart_config.get('colors', {})
        
        # Get color from preferences or fallback to default
        color = chart_colors.get(color_key, self.colors.get(color_key, self.colors['primary']))
        
        if chart_type == 'line':
            return go.Scatter(
                x=x_data,
                y=y_data,
                mode='lines+markers',
                line=dict(color=color, width=3),
                marker=dict(size=8, color=color),
                name=name,
                hovertemplate=hovertemplate,
                **kwargs
            )
        elif chart_type == 'bar':
            return go.Bar(
                x=x_data,
                y=y_data,
                marker=dict(color=color),
                name=name,
                hovertemplate=hovertemplate,
                **kwargs
            )
        else:
            # Default to bar chart
            return go.Bar(
                x=x_data,
                y=y_data,
                marker=dict(color=color),
                name=name,
                hovertemplate=hovertemplate,
                **kwargs
            )
    
    def _get_chart_type(self, chart_name: str) -> str:
        """
        Get configured chart type for a specific chart.
        
        Args:
            chart_name: Name of chart in CHART_PREFERENCES
            
        Returns:
            Chart type string
        """
        return self.chart_preferences.get(chart_name, {}).get('type', 'bar')
    
    def create_monthly_events_trend(self, monthly_data: Dict[str, Any]) -> str:
        """
        Create a line chart showing total events per month.
        
        Args:
            monthly_data: Dictionary with monthly statistics
            
        Returns:
            HTML string of the chart
        """
        try:
            if not monthly_data.get('has_trends', False):
                return self._create_no_data_chart("Month-to-Month Trends", monthly_data.get('reason', 'No data available'))
            
            months = list(monthly_data['months'].keys())
            events = [monthly_data['months'][month]['total_events'] for month in months]
            
            # Create formatted month labels
            month_labels = [monthly_data['months'][month]['month_name'] for month in months]
            
            fig = go.Figure()
            
            # Get chart type from configuration
            chart_type = self._get_chart_type('monthly_events_trend')
            
            # Create trace based on configuration
            trace = self._create_trace_by_type(
                chart_type=chart_type,
                chart_name='monthly_events_trend',
                x_data=month_labels,
                y_data=events,
                color_key='primary',
                name='Total Events',
                hovertemplate='<b>%{x}</b><br>Events: %{y:,}<extra></extra>'
            )
            
            fig.add_trace(trace)
            
            layout = self.base_layout.copy()
            layout.update({
                'title': {
                    'text': 'Security Events Per Month',
                    'font': {'size': 18, 'color': self.colors['dark']},
                    'x': 0.5
                },
                'xaxis': {
                    'title': 'Month',
                    'showgrid': True,
                    'gridcolor': '#f0f0f0'
                },
                'yaxis': {
                    'title': 'Number of Events',
                    'showgrid': True,
                    'gridcolor': '#f0f0f0'
                },
                'hovermode': 'x unified'
            })
            
            fig.update_layout(layout)
            
            return self._convert_to_html(fig)
            
        except Exception as e:
            logger.error(f"Failed to create monthly events trend: {e}")
            return self._create_error_chart("Monthly Events Trend", str(e))
    
    def create_attack_types_stacked_bar(self, monthly_data: Dict[str, Any], top_n: int = 5) -> str:
        """
        Create a stacked bar chart showing top attack types per month.
        
        Args:
            monthly_data: Dictionary with monthly statistics
            top_n: Number of top attack types to show
            
        Returns:
            HTML string of the chart
        """
        try:
            if not monthly_data.get('has_trends', False):
                return self._create_no_data_chart("Top Attack Types Per Month", monthly_data.get('reason', 'No data available'))
            
            months = list(monthly_data['months'].keys())
            month_labels = [monthly_data['months'][month]['month_name'] for month in months]
            
            # Get top attack types across all months
            all_attacks = {}
            for month in months:
                attacks = monthly_data['months'][month]['attack_types']
                for attack, attack_info in attacks.items():
                    if isinstance(attack_info, dict):
                        count = attack_info.get('count', 0)
                    else:
                        # Handle old format (just count)
                        count = attack_info
                    all_attacks[attack] = all_attacks.get(attack, 0) + count
            
            top_attacks = sorted(all_attacks.items(), key=lambda x: x[1], reverse=True)[:top_n]
            top_attack_names = [attack[0] for attack in top_attacks]
            
            fig = go.Figure()
            
            # Add trace for each attack type
            for i, attack_name in enumerate(top_attack_names):
                values = []
                for month in months:
                    attacks = monthly_data['months'][month]['attack_types']
                    attack_info = attacks.get(attack_name, 0)
                    if isinstance(attack_info, dict):
                        count = attack_info.get('count', 0)
                    else:
                        # Handle old format (just count)
                        count = attack_info
                    values.append(count)
                
                fig.add_trace(go.Bar(
                    x=month_labels,
                    y=values,
                    name=attack_name,
                    marker_color=self.chart_colors[i % len(self.chart_colors)],
                    hovertemplate=f'<b>{attack_name}</b><br>%{{x}}<br>Events: %{{y:,}}<extra></extra>'
                ))
            
            layout = self.base_layout.copy()
            layout.update({
                'title': {
                    'text': f'Top {top_n} Attack Types Per Month',
                    'font': {'size': 18, 'color': self.colors['dark']},
                    'x': 0.5
                },
                'xaxis': {'title': 'Month'},
                'yaxis': {'title': 'Number of Events'},
                'barmode': 'stack',
                'hovermode': 'x unified'
            })
            
            fig.update_layout(layout)
            
            return self._convert_to_html(fig)
            
        except Exception as e:
            logger.error(f"Failed to create attack types stacked bar: {e}")
            return self._create_error_chart("Attack Types Per Month", str(e))
    
    def create_attack_volume_trends(self, monthly_data: Dict[str, Any]) -> str:
        """
        Create line charts for attack volume metrics over time.
        
        Args:
            monthly_data: Dictionary containing monthly statistics
            
        Returns:
            HTML string of the chart
        """
        try:
            if not monthly_data.get('has_trends', False):
                return self._create_no_data_chart("Attack Volume Trends", monthly_data.get('reason', 'No data available'))
            
            months = list(monthly_data['months'].keys())
            month_labels = [monthly_data['months'][month]['month_name'] for month in months]
            
            # Extract volume and packet metrics
            total_mbits = [monthly_data['months'][month]['total_mbits'] for month in months]
            total_packets = [monthly_data['months'][month]['total_packets'] for month in months]
            max_pps = [monthly_data['months'][month]['max_pps'] for month in months]
            max_bps = [monthly_data['months'][month]['max_bps'] for month in months]
            
            # Convert volume to configured unit
            volume_config = VOLUME_UNIT_CONFIGS[VOLUME_UNIT]
            # Convert Mbits to bytes first (divide by 8), then to target unit
            total_volume = [mbits / 8 / volume_config['divider'] for mbits in total_mbits]
            
            # Convert packets to configured unit
            packet_config = PACKET_UNIT_CONFIGS[PACKET_UNIT]
            converted_packets = [packets / packet_config['divider'] for packets in total_packets]
            
            # Convert max_bps to configured bandwidth unit
            bandwidth_config = get_bandwidth_unit_config()
            max_bandwidth_values = [bps / bandwidth_config['divider'] for bps in max_bps]
            
            # Create subplots with 4 rows now
            fig = make_subplots(
                rows=4, cols=1,
                subplot_titles=(
                    volume_config['chart_title'], 
                    packet_config['chart_title'],
                    'Attack Max PPS', 
                    bandwidth_config['chart_title']
                ),
                vertical_spacing=0.06
            )
            
            # Get chart type from configuration
            chart_type = self._get_chart_type('attack_volume_trends')
            
            # Total Volume in configured unit (Row 1)
            volume_trace = self._create_trace_by_type(
                chart_type=chart_type,
                chart_name='attack_volume_trends',
                x_data=month_labels,
                y_data=total_volume,
                color_key='volume',
                name=f'Total {volume_config["display_name"]}',
                hovertemplate=f'<b>%{{x}}</b><br>Total {volume_config["display_name"]}: %{{y:,.2f}}<extra></extra>'
            )
            fig.add_trace(volume_trace, row=1, col=1)
            
            # Total Packets in configured unit (Row 2) 
            packets_trace = self._create_trace_by_type(
                chart_type=chart_type,
                chart_name='attack_volume_trends',
                x_data=month_labels,
                y_data=converted_packets,
                color_key='packets',
                name=f'Total Packets {packet_config["display_name"]}',
                hovertemplate=f'<b>%{{x}}</b><br>Packets {packet_config["display_name"]}: %{{y:,.2f}}<extra></extra>'
            )
            fig.add_trace(packets_trace, row=2, col=1)
            
            # Max PPS (Row 3)
            pps_trace = self._create_trace_by_type(
                chart_type=chart_type,
                chart_name='attack_volume_trends',
                x_data=month_labels,
                y_data=max_pps,
                color_key='pps',
                name='Max PPS',
                hovertemplate='<b>%{x}</b><br>Max PPS: %{y:,.0f}<extra></extra>'
            )
            fig.add_trace(pps_trace, row=3, col=1)
            
            # Max bandwidth (Row 4)
            bandwidth_trace = self._create_trace_by_type(
                chart_type=chart_type,
                chart_name='attack_volume_trends',
                x_data=month_labels,
                y_data=max_bandwidth_values,
                color_key='bandwidth',
                name=bandwidth_config['chart_name'],
                hovertemplate=bandwidth_config['hover_template']
            )
            fig.add_trace(bandwidth_trace, row=4, col=1)
            
            # Update layout to match monthly events styling
            layout = self.base_layout.copy()
            layout.update({
                'title': {
                    'text': 'Attack Volume Trends Over Time',
                    'font': {'size': 18, 'color': self.colors['dark']},
                    'x': 0.5
                },
                'height': 1000,  # Increased height for 4 subplots
                'showlegend': False,
                'hovermode': 'x unified'
            })
            
            fig.update_layout(layout)
            
            # Update axes to match monthly events styling
            fig.update_xaxes(showgrid=True, gridcolor='#f0f0f0')
            fig.update_yaxes(showgrid=True, gridcolor='#f0f0f0')
            
            return self._convert_to_html(fig)
            
        except Exception as e:
            logger.error(f"Failed to create attack volume trends: {e}")
            return self._create_error_chart("Attack Volume Trends", str(e))
    
    def create_hourly_heatmap(self, monthly_data: Dict[str, Any]) -> str:
        """
        Create a heatmap showing attack intensity by month and hour of day.
        
        Args:
            monthly_data: Dictionary with monthly statistics
            
        Returns:
            HTML string of the chart
        """
        try:
            if not monthly_data.get('has_trends', False):
                return self._create_no_data_chart("Attack Intensity Heatmap", monthly_data.get('reason', 'No data available'))
            
            months = list(monthly_data['months'].keys())
            month_labels = [monthly_data['months'][month]['month_name'] for month in months]
            
            # Create matrix for heatmap (months x hours)
            heatmap_data = []
            for month in months:
                hourly_dist = monthly_data['months'][month]['hourly_distribution']
                heatmap_data.append(hourly_dist)
            
            hours = list(range(24))
            
            # Get colorscale from configuration
            chart_config = self.chart_preferences.get('hourly_heatmap', {})
            colorscale = chart_config.get('colorscale', 'Blues')
            
            fig = go.Figure(data=go.Heatmap(
                z=heatmap_data,
                x=hours,
                y=month_labels,
                colorscale=colorscale,  # Use configured colorscale
                hovertemplate='<b>%{y}</b><br>Hour: %{x}:00<br>Events: %{z:,}<extra></extra>',
                colorbar=dict(title='Number of Events')
            ))
            
            layout = self.base_layout.copy()
            layout.update({
                'title': {
                    'text': 'Attack Intensity by Month and Hour of Day',
                    'font': {'size': 18, 'color': self.colors['dark']},
                    'x': 0.5
                },
                'xaxis': {
                    'title': 'Hour of Day',
                    'tickvals': list(range(0, 24, 2)),
                    'ticktext': [f'{h:02d}:00' for h in range(0, 24, 2)]
                },
                'yaxis': {'title': 'Month'},
                'height': 400
            })
            
            fig.update_layout(layout)
            
            return self._convert_to_html(fig)
            
        except Exception as e:
            logger.error(f"Failed to create hourly heatmap: {e}")
            return self._create_error_chart("Hourly Attack Heatmap", str(e))
    
    def create_attack_type_pie_chart(self, holistic_data: Dict[str, Any], top_n: int = 10) -> str:
        """
        Create a pie chart showing attack type distribution.
        
        Args:
            holistic_data: Dictionary with holistic analysis data
            top_n: Number of top attack types to show
            
        Returns:
            HTML string of the chart
        """
        try:
            attack_types = holistic_data.get('attack_types', {})
            
            if not attack_types:
                return self._create_no_data_chart("Attack Type Distribution", "No attack data available")
            
            # Get top attack types
            attack_counts = {}
            for attack, attack_info in attack_types.items():
                if isinstance(attack_info, dict):
                    count = attack_info.get('count', 0)
                else:
                    # Handle old format (just count)
                    count = attack_info
                attack_counts[attack] = count
            
            sorted_attacks = sorted(attack_counts.items(), key=lambda x: x[1], reverse=True)
            top_attacks = sorted_attacks[:top_n]
            
            # Group remaining attacks as "Others"
            if len(sorted_attacks) > top_n:
                others_count = sum(count for _, count in sorted_attacks[top_n:])
                top_attacks.append(("Others", others_count))
            
            labels = [attack[0] for attack in top_attacks]
            values = [attack[1] for attack in top_attacks]
            colors = self.chart_colors[:len(labels)]
            
            fig = go.Figure(data=[go.Pie(
                labels=labels,
                values=values,
                hole=0.3,
                marker=dict(colors=colors),
                hovertemplate='<b>%{label}</b><br>Events: %{value:,}<br>Percentage: %{percent}<extra></extra>'
            )])
            
            layout = self.base_layout.copy()
            layout.update({
                'title': {
                    'text': 'Attack Type Distribution',
                    'font': {'size': 18, 'color': self.colors['dark']},
                    'x': 0.5
                },
                'showlegend': True,
                'legend': {
                    'orientation': 'v',
                    'yanchor': 'middle',
                    'y': 0.5,
                    'xanchor': 'left',
                    'x': 1.05
                }
            })
            
            fig.update_layout(layout)
            
            return self._convert_to_html(fig)
            
        except Exception as e:
            logger.error(f"Failed to create attack type pie chart: {e}")
            return self._create_error_chart("Attack Type Distribution", str(e))
    
    def create_top_source_ips_bar(self, holistic_data: Dict[str, Any], top_n: int = 20) -> str:
        """
        Create a horizontal bar chart showing top source IPs.
        
        Args:
            holistic_data: Dictionary with holistic analysis data
            top_n: Number of top IPs to show
            
        Returns:
            HTML string of the chart
        """
        try:
            source_ips = holistic_data.get('top_source_ips', {})
            
            if not source_ips:
                return self._create_no_data_chart("Top Source IPs", "No source IP data available")
            
            # Get top IPs (already sorted in data processing)
            top_ips = list(source_ips.items())[:top_n]
            
            ips = [ip[0] for ip in top_ips]
            counts = [ip[1] for ip in top_ips]
            
            # Reverse for horizontal bar chart (top to bottom)
            ips.reverse()
            counts.reverse()
            
            fig = go.Figure(data=[go.Bar(
                x=counts,
                y=ips,
                orientation='h',
                marker=dict(color=self.colors['primary']),
                hovertemplate='<b>%{y}</b><br>Events: %{x:,}<extra></extra>'
            )])
            
            layout = self.base_layout.copy()
            layout.update({
                'title': {
                    'text': f'Top {min(len(ips), top_n)} Source IP Addresses',
                    'font': {'size': 18, 'color': self.colors['dark']},
                    'x': 0.5
                },
                'xaxis': {'title': 'Number of Events'},
                'yaxis': {'title': 'Source IP Address'},
                'height': max(400, len(ips) * 25),
                'showlegend': False
            })
            
            fig.update_layout(layout)
            
            return self._convert_to_html(fig)
            
        except Exception as e:
            logger.error(f"Failed to create top source IPs bar chart: {e}")
            return self._create_error_chart("Top Source IPs", str(e))
    
    def create_protocol_distribution_chart(self, holistic_data: Dict[str, Any]) -> str:
        """
        Create a bar chart showing protocol distribution.
        
        Args:
            holistic_data: Dictionary with holistic analysis data
            
        Returns:
            HTML string of the chart
        """
        try:
            protocols = holistic_data.get('protocols', {})
            
            if not protocols:
                return self._create_no_data_chart("Protocol Distribution", "No protocol data available")
            
            # Sort protocols by count
            sorted_protocols = sorted(protocols.items(), key=lambda x: x[1], reverse=True)
            
            protocol_names = [p[0] for p in sorted_protocols]
            protocol_counts = [p[1] for p in sorted_protocols]
            
            fig = go.Figure(data=[go.Bar(
                x=protocol_names,
                y=protocol_counts,
                marker=dict(color=self.colors['secondary']),
                hovertemplate='<b>%{x}</b><br>Events: %{y:,}<extra></extra>'
            )])
            
            layout = self.base_layout.copy()
            layout.update({
                'title': {
                    'text': 'Attack Distribution by Protocol',
                    'font': {'size': 18, 'color': self.colors['dark']},
                    'x': 0.5
                },
                'xaxis': {'title': 'Protocol'},
                'yaxis': {'title': 'Number of Events'},
                'showlegend': False
            })
            
            fig.update_layout(layout)
            
            return self._convert_to_html(fig)
            
        except Exception as e:
            logger.error(f"Failed to create protocol distribution chart: {e}")
            return self._create_error_chart("Protocol Distribution", str(e))
    
    def create_daily_timeline_chart(self, holistic_data: Dict[str, Any]) -> str:
        """
        Create a timeline chart showing daily attack events.
        
        Args:
            holistic_data: Dictionary with holistic analysis data
            
        Returns:
            HTML string of the chart
        """
        try:
            daily_data = holistic_data.get('daily_distribution', {})
            
            if not daily_data:
                return self._create_no_data_chart("Daily Attack Timeline", "No daily data available")
            
            # Sort dates
            sorted_dates = sorted(daily_data.items())
            dates = [datetime.strptime(date_str, '%Y-%m-%d') for date_str, _ in sorted_dates]
            counts = [count for _, count in sorted_dates]
            
            fig = go.Figure(data=[go.Scatter(
                x=dates,
                y=counts,
                mode='lines+markers',
                line=dict(color=self.colors['primary'], width=2),
                marker=dict(size=4),
                fill='tonexty',
                fillcolor=f'rgba(0, 63, 127, 0.1)',
                hovertemplate='<b>%{x|%Y-%m-%d}</b><br>Events: %{y:,}<extra></extra>'
            )])
            
            layout = self.base_layout.copy()
            layout.update({
                'title': {
                    'text': 'Daily Attack Events Timeline',
                    'font': {'size': 18, 'color': self.colors['dark']},
                    'x': 0.5
                },
                'xaxis': {
                    'title': 'Date',
                    'showgrid': True,
                    'gridcolor': '#f0f0f0'
                },
                'yaxis': {
                    'title': 'Number of Events',
                    'showgrid': True,
                    'gridcolor': '#f0f0f0'
                },
                'showlegend': False
            })
            
            fig.update_layout(layout)
            
            return self._convert_to_html(fig)
            
        except Exception as e:
            logger.error(f"Failed to create daily timeline chart: {e}")
            return self._create_error_chart("Daily Timeline", str(e))
    
    def create_summary_statistics_table(self, holistic_data: Dict[str, Any], monthly_data: Dict[str, Any]) -> str:
        """
        Create an HTML table with summary statistics.
        
        Args:
            holistic_data: Dictionary with holistic analysis data
            monthly_data: Dictionary with monthly analysis data
            
        Returns:
            HTML string of the statistics table
        """
        try:
            date_range = holistic_data.get('date_range', {})
            volume_config = VOLUME_UNIT_CONFIGS[VOLUME_UNIT]
            packet_config = PACKET_UNIT_CONFIGS[PACKET_UNIT]
            
            # Convert volume to configured unit (Mbits to bytes first, then to target unit)
            total_volume_converted = holistic_data.get('total_mbits', 0) / 8 / volume_config['divider']
            
            # Convert packets to configured unit
            total_packets_converted = holistic_data.get('total_packets', 0) / packet_config['divider']
            
            # Prepare stats with special handling for expandable fields
            # Regular stats (non-expandable)
            stats = [
                ("Total Security Events", format_number(holistic_data.get('total_events', 0))),
                ("Total Days", format_number(date_range.get('days', 0))),
                (volume_config['stats_label'], f"{total_volume_converted:,.2f}"),
                (packet_config['stats_label'], f"{total_packets_converted:,.2f}")
            ]
            
            # Expandable stats data
            expandable_stats = [
                {
                    'label': 'Unique Attack Source IPs',
                    'value': format_number(holistic_data.get('unique_source_ips', 0)),
                    'details': holistic_data.get('unique_source_ips_list', []),
                    'id': 'unique-source-ips-details',
                    'type': 'list'
                },
                {
                    'label': 'Unique Attacked Destination IPs', 
                    'value': format_number(holistic_data.get('unique_dest_ips', 0)),
                    'details': holistic_data.get('unique_dest_ips_list', []),
                    'id': 'unique-dest-ips-details',
                    'type': 'list'
                },
                {
                    'label': 'Unique Attack Types',
                    'value': format_number(len(holistic_data.get('attack_types', {}))),
                    'details': holistic_data.get('attack_types_details', []),
                    'id': 'unique-attack-types-details', 
                    'type': 'attack_types_details'
                },
                {
                    'label': 'Attack Max PPS',
                    'value': format_number(holistic_data.get('max_pps', 0)),
                    'details': holistic_data.get('max_pps_details'),
                    'id': 'max-pps-details',
                    'type': 'attack_details'
                },
                {
                    'label': get_bandwidth_unit_config()['stats_label'], 
                    'value': f"{format_number(round(holistic_data.get('max_bps', 0) / get_bandwidth_unit_config()['divider'], 2))} {get_bandwidth_unit_config()['unit_name']}",
                    'details': holistic_data.get('max_bps_details'),
                    'id': 'max-bps-details',
                    'type': 'attack_details'
                },
                {
                    'label': 'Complete Months for Trends',
                    'value': format_number(len(monthly_data.get('months', {}))),
                    'details': self._convert_month_keys_to_names(monthly_data.get('months', {})) if monthly_data.get('months') else [],
                    'id': 'months-trends-details',
                    'type': 'list'
                }
            ]
            
            # Special expandable field for Longest Attack Duration
            longest_attack_details = holistic_data.get('longest_attack_details')
            longest_attack_duration = holistic_data.get('longest_attack_duration', '00:00:00')
            
            html = """
            <div class="stats-grid">
            """
            
            # Add regular (non-expandable) stats
            for label, value in stats:
                html += f"""
                <div class="stat-card">
                    <div class="stat-value">{value}</div>
                    <div class="stat-label">{label}</div>
                </div>
                """
            
            # Add expandable stats
            for stat_config in expandable_stats:
                if stat_config['type'] == 'list' and stat_config['details']:
                    # Create list of (display_name, value) tuples for list-type expandables
                    details_list = [(item, item) for item in stat_config['details']]
                    html += self.create_expandable_stat_card_for_custom_data(
                        stat_config['label'],
                        stat_config['value'],
                        details_list,
                        stat_config['id']
                    )
                elif stat_config['type'] == 'attack_types_details' and stat_config['details']:
                    # For attack types with threat categories, format as (threat_category, attack_name) tuples
                    html += self.create_expandable_stat_card_for_custom_data(
                        stat_config['label'],
                        stat_config['value'],
                        stat_config['details'],  # Already in (threat_category, attack_name) format
                        stat_config['id']
                    )
                elif stat_config['type'] == 'attack_details' and stat_config['details']:
                    # For attack details, use the existing method
                    html += self._create_expandable_stat_card(
                        stat_config['label'],
                        stat_config['value'],
                        stat_config['details'],
                        stat_config['id']
                    )
                else:
                    # Fallback to regular card if no details available
                    html += f"""
                    <div class="stat-card">
                        <div class="stat-value">{stat_config['value']}</div>
                        <div class="stat-label">{stat_config['label']}</div>
                    </div>
                    """
            
            # Add expandable Longest Attack Duration card
            if longest_attack_details:
                html += self._create_expandable_stat_card(
                    "Longest Attack Duration",
                    longest_attack_duration,
                    longest_attack_details,
                    "longest-attack-details"
                )
            else:
                html += f"""
                <div class="stat-card">
                    <div class="stat-value">{longest_attack_duration}</div>
                    <div class="stat-label">Longest Attack Duration</div>
                </div>
                """
            
            html += """
            </div>
            """
            
            return html
            
        except Exception as e:
            logger.error(f"Failed to create summary statistics table: {e}")
            return f'<div class="warning">Failed to generate summary statistics: {e}</div>'
    
    def _create_no_data_chart(self, title: str, message: str) -> str:
        """
        Create a placeholder chart for when no data is available.
        
        Args:
            title: Chart title
            message: Message to display
            
        Returns:
            HTML string of placeholder chart
        """
        fig = go.Figure()
        
        fig.add_annotation(
            x=0.5, y=0.5,
            xref="paper", yref="paper",
            text=message,
            showarrow=False,
            font=dict(size=16, color=self.colors['dark']),
            align="center"
        )
        
        layout = self.base_layout.copy()
        layout.update({
            'title': {
                'text': title,
                'font': {'size': 18, 'color': self.colors['dark']},
                'x': 0.5
            },
            'xaxis': {'visible': False},
            'yaxis': {'visible': False},
            'height': 300
        })
        
        fig.update_layout(layout)
        
        return self._convert_to_html(fig)
    
    def _create_error_chart(self, title: str, error: str) -> str:
        """
        Create an error chart when chart generation fails.
        
        Args:
            title: Chart title
            error: Error message
            
        Returns:
            HTML string of error chart
        """
        return f"""
        <div class="chart-container">
            <h3>{title}</h3>
            <div class="warning">
                <strong>Error generating chart:</strong> {error}
            </div>
        </div>
        """
    
    def _create_expandable_stat_card(self, label: str, value: str, details_data: Dict[str, Any], details_id: str) -> str:
        """
        Create an expandable stat card with detailed information.
        
        Args:
            label: Display label for the stat
            value: Main value to display
            details_data: Dictionary containing detailed information
            details_id: Unique ID for the expandable section
            
        Returns:
            HTML string for expandable stat card
        """
        if not details_data or not details_data.get('details'):
            # Return normal stat card if no details available
            return f"""
                <div class="stat-card">
                    <div class="stat-value">{value}</div>
                    <div class="stat-label">{label}</div>
                </div>
                """
        
        # Extract relevant details for display
        attack_details = details_data['details']
        
        # Define the fields we want to display
        display_fields = [
            ('Start Time', 'Start Time'),
            ('End Time', 'End Time'),
            ('Device IP Address', 'Device IP Address'),
            ('Attack Name', 'Attack Name'),
            ('Policy Name', 'Policy Name'),
            ('Action', 'Action'),
            ('Attack ID', 'Attack ID'),
            ('Source IP Address', 'Source IP Address'),
            ('Source Port', 'Source Port'),
            ('Destination IP Address', 'Destination IP Address'),
            ('Protocol', 'Protocol'),
            ('Max pps', 'Max pps'),
            ('Max bps', 'Max bps')
        ]
        
        # Build details HTML
        details_html = ""
        for display_name, field_key in display_fields:
            field_value = attack_details.get(field_key, 'N/A')
            if field_value is None or str(field_value) == 'nan':
                field_value = 'N/A'
            details_html += f"""
                <div class="detail-row">
                    <span class="detail-label">{display_name}:</span>
                    <span class="detail-value">{field_value}</span>
                </div>
            """
        
        return f"""
            <div class="stat-card expandable-card">
                <div class="stat-value expandable-trigger" onclick="toggleDetails('{details_id}')" style="cursor: pointer; position: relative;">
                    {value}
                    <span class="expand-icon" id="{details_id}-icon">▼</span>
                </div>
                <div class="stat-label">{label} <small style="color: #6c757d;">(click to expand)</small></div>
                <div id="{details_id}" class="attack-details">
                    <div class="details-container">
                        <h4 style="margin: 0 0 10px 0; color: #003f7f; font-size: 14px;">Attack Details</h4>
                        {details_html}
                    </div>
                </div>
            </div>
        """
    
    def create_expandable_stat_card_for_custom_data(self, label: str, value: str, custom_fields: List[tuple], details_id: str) -> str:
        """
        Create an expandable stat card with custom field data.
        
        This is a helper method for creating expandable cards for other fields like 
        "Top Source IP", "Highest Volume Attack", etc.
        
        Args:
            label: Display label for the stat
            value: Main value to display  
            custom_fields: List of (display_name, field_value) tuples for the details
            details_id: Unique ID for the expandable section
            
        Returns:
            HTML string for expandable stat card
            
        Example usage:
            custom_fields = [
                ('Attack Name', 'DDoS Flood'),
                ('Source IP', '192.168.1.100'),
                ('Volume (MB)', '1,250.5'),
                ('Duration', '2h:15m:30s')
            ]
            html = visualizer.create_expandable_stat_card_for_custom_data(
                "Highest Volume Attack", "1,250.5 MB", custom_fields, "highest-volume-attack"
            )
        """
        if not custom_fields:
            # Return normal stat card if no details available
            return f"""
                <div class="stat-card">
                    <div class="stat-value">{value}</div>
                    <div class="stat-label">{label}</div>
                </div>
                """
        
        # Check if this is a simple list (all tuples have same display_name as field_value)
        is_simple_list = all(display_name == field_value for display_name, field_value in custom_fields)
        
        if is_simple_list:
            # Create compact list format - single block with all values (no duplicate label)
            values_list = [str(field_value) for display_name, field_value in custom_fields if field_value and str(field_value) != 'N/A']
            details_html = f"""
                <div class="detail-value" style="white-space: pre-line; margin: 0; padding: 0;">{chr(10).join(values_list)}</div>
            """
        else:
            # Build details HTML from custom fields (for non-list data)
            details_html = ""
            for display_name, field_value in custom_fields:
                if field_value is None or str(field_value) == 'nan':
                    field_value = 'N/A'
                details_html += f"""
                    <div class="detail-row">
                        <span class="detail-label">{display_name}:</span>
                        <span class="detail-value">{field_value}</span>
                    </div>
                """
        
        return f"""
            <div class="stat-card expandable-card">
                <div class="stat-value expandable-trigger" onclick="toggleDetails('{details_id}')" style="cursor: pointer; position: relative;">
                    {value}
                    <span class="expand-icon" id="{details_id}-icon">▼</span>
                </div>
                <div class="stat-label">{label} <small style="color: #6c757d;">(click to expand)</small></div>
                <div id="{details_id}" class="attack-details">
                    <div class="details-container">
                        <h4 style="margin: 0 0 10px 0; color: #003f7f; font-size: 14px;">Details</h4>
                        {details_html}
                    </div>
                </div>
            </div>
        """
    
    def _convert_month_keys_to_names(self, months_dict: dict) -> list:
        """
        Convert month keys like '2025-08' to readable month names like 'August 2025'.
        
        Args:
            months_dict: Dictionary with month keys in YYYY-MM format
            
        Returns:
            List of readable month names sorted chronologically
        """
        import datetime
        
        month_names = []
        for month_key in sorted(months_dict.keys()):
            try:
                # Parse the month key (format: YYYY-MM)
                year, month = month_key.split('-')
                # Create a date object to get the month name
                date_obj = datetime.date(int(year), int(month), 1)
                # Format as "Month Year" (e.g., "August 2025")
                month_name = date_obj.strftime('%B %Y')
                month_names.append(month_name)
            except (ValueError, IndexError):
                # Fallback to original key if parsing fails
                month_names.append(month_key)
        
        return month_names

    def update_chart_preferences(self, chart_name: str, preferences: Dict[str, Any]) -> bool:
        """
        Update chart preferences for a specific chart.
        
        Args:
            chart_name: Name of chart to update
            preferences: Dictionary with new preferences
            
        Returns:
            True if update successful, False otherwise
        """
        try:
            if chart_name not in self.available_types:
                logger.warning(f"Unknown chart name: {chart_name}")
                return False
            
            # Validate chart type if provided
            if 'type' in preferences:
                chart_type = preferences['type']
                if chart_type not in self.available_types[chart_name]:
                    logger.warning(f"Invalid chart type '{chart_type}' for {chart_name}. Available: {self.available_types[chart_name]}")
                    return False
            
            # Update preferences
            if chart_name not in self.chart_preferences:
                self.chart_preferences[chart_name] = {}
            
            self.chart_preferences[chart_name].update(preferences)
            logger.info(f"Updated chart preferences for {chart_name}: {preferences}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to update chart preferences for {chart_name}: {e}")
            return False
    
    def get_chart_preferences(self, chart_name: str = None) -> Dict[str, Any]:
        """
        Get chart preferences for a specific chart or all charts.
        
        Args:
            chart_name: Name of chart (None for all charts)
            
        Returns:
            Dictionary with chart preferences
        """
        if chart_name:
            return self.chart_preferences.get(chart_name, {})
        return self.chart_preferences.copy()
    
    def get_available_chart_types(self, chart_name: str = None) -> Dict[str, List[str]]:
        """
        Get available chart types for a specific chart or all charts.
        
        Args:
            chart_name: Name of chart (None for all charts)
            
        Returns:
            Dictionary with available chart types
        """
        if chart_name:
            return {chart_name: self.available_types.get(chart_name, [])}
        return self.available_types.copy()
    
    def reset_chart_preferences(self, chart_name: str = None) -> bool:
        """
        Reset chart preferences to defaults.
        
        Args:
            chart_name: Name of chart to reset (None for all charts)
            
        Returns:
            True if reset successful, False otherwise
        """
        try:
            if chart_name:
                if chart_name in CHART_PREFERENCES:
                    self.chart_preferences[chart_name] = CHART_PREFERENCES[chart_name].copy()
                    logger.info(f"Reset chart preferences for {chart_name}")
                else:
                    logger.warning(f"No default preferences found for {chart_name}")
                    return False
            else:
                # Reset all preferences
                self.chart_preferences = {}
                for name, prefs in CHART_PREFERENCES.items():
                    self.chart_preferences[name] = prefs.copy()
                logger.info("Reset all chart preferences to defaults")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to reset chart preferences: {e}")
            return False
