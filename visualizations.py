"""
Visualization module for creating interactive charts and graphs.

This module creates professional, interactive visualizations using Plotly
with Radware branding and styling for both technical and sales audiences.
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
    VOLUME_UNIT, VOLUME_UNIT_CONFIGS, PACKET_UNIT, PACKET_UNIT_CONFIGS
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
        
        logger.info("Initialized ForensicsVisualizer with Radware styling")
    
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
            
            fig.add_trace(go.Scatter(
                x=month_labels,
                y=events,
                mode='lines+markers',
                line=dict(color=self.colors['primary'], width=3),
                marker=dict(size=8, color=self.colors['primary']),
                name='Total Events',
                hovertemplate='<b>%{x}</b><br>Events: %{y:,}<extra></extra>'
            ))
            
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
            
            return fig.to_html(config=CHART_CONFIG, include_plotlyjs='inline')
            
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
                for attack, count in attacks.items():
                    all_attacks[attack] = all_attacks.get(attack, 0) + count
            
            top_attacks = sorted(all_attacks.items(), key=lambda x: x[1], reverse=True)[:top_n]
            top_attack_names = [attack[0] for attack in top_attacks]
            
            fig = go.Figure()
            
            # Add trace for each attack type
            for i, attack_name in enumerate(top_attack_names):
                values = []
                for month in months:
                    attacks = monthly_data['months'][month]['attack_types']
                    values.append(attacks.get(attack_name, 0))
                
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
            
            return fig.to_html(config=CHART_CONFIG, include_plotlyjs='inline')
            
        except Exception as e:
            logger.error(f"Failed to create attack types stacked bar: {e}")
            return self._create_error_chart("Attack Types Per Month", str(e))
    
    def create_attack_volume_trends(self, monthly_data: Dict[str, Any]) -> str:
        """
        Create line charts for attack volume metrics over time.
        
        Args:
            monthly_data: Dictionary with monthly statistics
            
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
            
            # Convert max_bps to Gbps
            max_gbps = [bps / 1_000_000_000 for bps in max_bps]
            
            # Create subplots with 4 rows now
            fig = make_subplots(
                rows=4, cols=1,
                subplot_titles=(
                    volume_config['chart_title'], 
                    packet_config['chart_title'],
                    'Attack Max PPS', 
                    'Attack Max Gbps'
                ),
                vertical_spacing=0.06
            )
            
            # Total Volume in configured unit (Row 1)
            fig.add_trace(go.Scatter(
                x=month_labels,
                y=total_volume,
                mode='lines+markers',
                line=dict(color=self.colors['primary'], width=3),
                marker=dict(size=8, color=self.colors['primary']),
                name=f'Total {volume_config["display_name"]}',
                hovertemplate=f'<b>%{{x}}</b><br>Total {volume_config["display_name"]}: %{{y:,.2f}}<extra></extra>'
            ), row=1, col=1)
            
            # Total Packets in configured unit (Row 2) 
            fig.add_trace(go.Scatter(
                x=month_labels,
                y=converted_packets,
                mode='lines+markers',
                line=dict(color=self.colors['secondary'], width=3),
                marker=dict(size=8, color=self.colors['secondary']),
                name=f'Total Packets {packet_config["display_name"]}',
                hovertemplate=f'<b>%{{x}}</b><br>Packets {packet_config["display_name"]}: %{{y:,.2f}}<extra></extra>'
            ), row=2, col=1)
            
            # Max PPS (Row 3)
            fig.add_trace(go.Scatter(
                x=month_labels,
                y=max_pps,
                mode='lines+markers',
                line=dict(color=self.colors['accent'], width=3),
                marker=dict(size=8, color=self.colors['accent']),
                name='Max PPS',
                hovertemplate='<b>%{x}</b><br>Max PPS: %{y:,.0f}<extra></extra>'
            ), row=3, col=1)
            
            # Max Gbps (Row 4)
            fig.add_trace(go.Scatter(
                x=month_labels,
                y=max_gbps,
                mode='lines+markers',
                line=dict(color=self.colors['success'], width=3),
                marker=dict(size=8, color=self.colors['success']),
                name='Max Gbps',
                hovertemplate='<b>%{x}</b><br>Max Gbps: %{y:,.2f}<extra></extra>'
            ), row=4, col=1)
            
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
            
            return fig.to_html(config=CHART_CONFIG, include_plotlyjs='inline')
            
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
            
            fig = go.Figure(data=go.Heatmap(
                z=heatmap_data,
                x=hours,
                y=month_labels,
                colorscale=[
                    [0, '#ffffff'],
                    [0.2, '#e3f2fd'],
                    [0.4, '#bbdefb'],
                    [0.6, '#90caf9'],
                    [0.8, '#42a5f5'],
                    [1, '#1e88e5']
                ],
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
            
            return fig.to_html(config=CHART_CONFIG, include_plotlyjs='inline')
            
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
            sorted_attacks = sorted(attack_types.items(), key=lambda x: x[1], reverse=True)
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
            
            return fig.to_html(config=CHART_CONFIG, include_plotlyjs='inline')
            
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
            
            return fig.to_html(config=CHART_CONFIG, include_plotlyjs='inline')
            
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
            
            return fig.to_html(config=CHART_CONFIG, include_plotlyjs='inline')
            
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
            
            return fig.to_html(config=CHART_CONFIG, include_plotlyjs='inline')
            
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
            
            stats = [
                ("Total Security Events", format_number(holistic_data.get('total_events', 0))),
                ("Total Days", format_number(date_range.get('days', 0))),
                ("Unique Attack Source IPs", format_number(holistic_data.get('unique_source_ips', 0))),
                ("Unique Attacked Destination IPs", format_number(holistic_data.get('unique_dest_ips', 0))),
                ("Unique Attack Types", format_number(len(holistic_data.get('attack_types', {})))),
                ("Attack Max PPS", format_number(holistic_data.get('max_pps', 0))),
                ("Attack Max Gbps", format_number(round(holistic_data.get('max_bps', 0) / 1_000_000_000, 2))),
                (volume_config['stats_label'], f"{total_volume_converted:,.2f}"),
                (packet_config['stats_label'], f"{total_packets_converted:,.2f}"),
                ("Longest Attack Duration", holistic_data.get('longest_attack_duration', '00:00:00')),
                ("Complete Months for Trends", format_number(len(monthly_data.get('months', {}))))

            ]
            html = """
            <div class="stats-grid">
            """
            
            for label, value in stats:
                html += f"""
                <div class="stat-card">
                    <div class="stat-value">{value}</div>
                    <div class="stat-label">{label}</div>
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
        
        return fig.to_html(config=CHART_CONFIG, include_plotlyjs='inline')
    
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