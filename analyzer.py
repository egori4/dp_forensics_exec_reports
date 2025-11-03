#!/usr/bin/env python3
"""
DefensePro Forensics Data Analysis & Report Generator

Main orchestrator script that processes DefensePro forensics data from CSV files
and generates comprehensive HTML and PDF reports with interactive visualizations.

Usage:
    python analyzer.py [options]

Example:
    python analyzer.py --input-dir forensics_input --output-dir report_files --verbose
"""

import argparse
import logging
import sys
import tempfile
from pathlib import Path
from typing import List, Dict, Any
import time
from datetime import datetime
import shutil

# Check if config.py exists, if not create it from config_example.py
config_path = Path(__file__).parent / 'config.py'
config_example_path = Path(__file__).parent / 'config_example.py'

if not config_path.exists():
    if config_example_path.exists():
        print(f"⚙️  Creating config.py from config_example.py...")
        shutil.copy2(config_example_path, config_path)
        print(f"✅ config.py created successfully!")
    else:
        print(f"❌ ERROR: config_example.py not found!")
        print(f"   Please ensure config_example.py exists in the script directory.")
        sys.exit(1)

# Import our modules
from utils import (
    setup_logging, get_file_info, extract_zip_files, validate_csv_structure,
    check_memory_usage, format_duration
)
from data_processor import ForensicsDataProcessor
from report_generator import ReportGenerator
from config_b import REQUIRED_COLUMNS, OUTPUT_FORMATS

logger = logging.getLogger(__name__)


class ForensicsAnalyzer:
    """
    Main orchestrator class for forensics data analysis and report generation.
    """
    
    def __init__(self, input_dir: Path, output_dir: Path, verbose: bool = False):
        """
        Initialize the analyzer.
        
        Args:
            input_dir: Directory containing input files
            output_dir: Directory for output reports
            verbose: Enable verbose logging
        """
        self.input_dir = Path(input_dir)
        self.output_dir = Path(output_dir)
        self.verbose = verbose
        
        # Setup logging
        setup_logging(verbose)
        logger.info("Initialized DefensePro Forensics Analyzer")
        
        # Ensure directories exist
        self.input_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize components
        self.report_generator = ReportGenerator(self.output_dir)
        
        logger.info(f"Input directory: {self.input_dir}")
        logger.info(f"Output directory: {self.output_dir}")
    
    def discover_input_files(self) -> List[Path]:
        """
        Discover CSV and ZIP files in the input directory.
        
        Returns:
            List of input file paths (deduplicated)
        """
        logger.info("Discovering input files...")
        
        input_files = []
        
        # Find CSV files
        csv_files = list(self.input_dir.glob("*.csv"))
        input_files.extend(csv_files)
        
        # Find ZIP files
        zip_files = list(self.input_dir.glob("*.zip"))
        
        # Extract ZIP files and add CSV files from them
        temp_dir = None
        if zip_files:
            temp_dir = Path(tempfile.mkdtemp(prefix="forensics_temp_"))
            
            for zip_file in zip_files:
                logger.info(f"Extracting ZIP file: {zip_file.name}")
                extracted_files = extract_zip_files(zip_file, temp_dir)
                input_files.extend(extracted_files)
        
        # Remove duplicates based on filename and size
        unique_files = self._deduplicate_files(input_files)
        
        if not unique_files:
            logger.error(f"No CSV or ZIP files found in {self.input_dir}")
            return []
        
        logger.info(f"Found {len(unique_files)} file(s) to process:")
        for file_path in unique_files:
            file_info = get_file_info(file_path)
            logger.info(f"  - {file_info['name']} ({file_info['size_formatted']})")
        
        return unique_files
    
    def _deduplicate_files(self, file_list: List[Path]) -> List[Path]:
        """
        Remove duplicate files based on filename and size.
        
        Args:
            file_list: List of file paths to deduplicate
            
        Returns:
            List of unique file paths
        """
        seen_files = {}  # (name, size) -> path
        unique_files = []
        
        for file_path in file_list:
            try:
                file_info = get_file_info(file_path)
                key = (file_info['name'], file_info['size_bytes'])  # Use correct key name
                
                if key not in seen_files:
                    seen_files[key] = file_path
                    unique_files.append(file_path)
                else:
                    logger.info(f"Skipping duplicate file: {file_info['name']} ({file_info['size_formatted']})")
                    
            except Exception as e:
                logger.warning(f"Failed to get info for file {file_path}: {e}")
                continue
        
        if len(file_list) > len(unique_files):
            logger.info(f"Removed {len(file_list) - len(unique_files)} duplicate file(s)")
        
        return unique_files
    
    def validate_input_file(self, file_path: Path) -> bool:
        """
        Validate that an input file has the required structure.
        
        Args:
            file_path: Path to the file to validate
            
        Returns:
            True if file is valid, False otherwise
        """
        logger.info(f"Validating file structure: {file_path.name}")
        
        try:
            is_valid, missing_columns = validate_csv_structure(file_path, REQUIRED_COLUMNS)
            
            if not is_valid:
                logger.error(f"File {file_path.name} is missing required columns: {missing_columns}")
                return False
            
            logger.info(f"File validation passed: {file_path.name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to validate file {file_path.name}: {e}")
            return False
    
    def process_single_file(
        self, 
        file_path: Path, 
        formats: List[str] = None
    ) -> Dict[str, Any]:
        """
        Process a single forensics file and generate reports.
        
        Args:
            file_path: Path to the file to process
            formats: List of output formats to generate (defaults to OUTPUT_FORMATS from config)
            
        Returns:
            Dictionary with processing results
        """
        if formats is None:
            formats = OUTPUT_FORMATS.copy()
        start_time = time.time()
        logger.info("-" * 60)
        logger.info(f"Starting processing of {file_path.name}")
        
        results = {
            'file_name': file_path.name,
            'success': False,
            'generated_files': {},
            'error_message': None,
            'processing_time': 0,
            'file_info': get_file_info(file_path)
        }
        
        try:
            # Check memory before starting
            memory_stats = check_memory_usage()
            if memory_stats['warning']:
                logger.warning("High memory usage detected before processing")
            
            # Validate file structure
            if not self.validate_input_file(file_path):
                results['error_message'] = "File validation failed"
                return results
            
            # Initialize data processor
            processor = ForensicsDataProcessor(file_path)
            
            # Analyze file structure
            file_analysis = processor.analyze_file_structure()
            logger.info(f"File analysis complete: {file_analysis['estimated_rows']:,} estimated rows")
            
            # Scan for date range
            start_date, end_date = processor.scan_date_range()
            logger.info(f"Date range: {start_date.date()} to {end_date.date()}")
            
            # Process monthly trends
            logger.info("Processing monthly trend analysis...")
            monthly_data = processor.process_monthly_trends()
            
            # Process holistic analysis
            logger.info("Processing holistic analysis...")
            holistic_data = processor.process_holistic_analysis()
            
            # Get processing summary
            processing_summary = processor.get_processing_summary()
            
            # Generate reports
            logger.info(f"Generating reports in formats: {formats}")
            generated_files = self.report_generator.generate_reports(
                file_path.name,
                holistic_data,
                monthly_data,
                processing_summary,
                formats
            )
            
            # Update results
            results['success'] = True
            results['generated_files'] = {fmt: str(path) for fmt, path in generated_files.items()}
            results['processing_time'] = time.time() - start_time
            
            logger.info(f"Successfully processed {file_path.name} in {format_duration(results['processing_time'])}")
            
            # Log generated files
            for fmt, path in generated_files.items():
                logger.info(f"Generated {fmt.upper()} report: {path}")
            
            return results
            
        except Exception as e:
            results['error_message'] = str(e)
            results['processing_time'] = time.time() - start_time
            logger.error(f"Failed to process {file_path.name}: {e}")
            return results
    
    def process_all_files(self, formats: List[str] = None) -> Dict[str, Any]:
        """
        Process all discovered input files and generate reports.
        
        Args:
            formats: List of output formats to generate (defaults to OUTPUT_FORMATS from config)
            
        Returns:
            Summary of all processing results
        """
        if formats is None:
            formats = OUTPUT_FORMATS.copy()
        overall_start_time = time.time()
        logger.info("Starting batch processing of all input files")
        
        # Discover input files
        input_files = self.discover_input_files()
        
        if not input_files:
            logger.error("No input files found to process")
            return {
                'success': False,
                'error_message': 'No input files found',
                'total_files': 0,
                'processed_files': 0,
                'failed_files': 0,
                'total_processing_time': 0.0,
                'results': []
            }
        
        # Process each file
        results = []
        successful_count = 0
        failed_count = 0
        
        for i, file_path in enumerate(input_files, 1):
            logger.info(f"Processing file {i}/{len(input_files)}: {file_path.name}")
            
            try:
                result = self.process_single_file(file_path, formats)
                results.append(result)
                
                if result['success']:
                    successful_count += 1
                else:
                    failed_count += 1
                    
            except Exception as e:
                logger.error(f"Unexpected error processing {file_path.name}: {e}")
                results.append({
                    'file_name': file_path.name,
                    'success': False,
                    'error_message': f"Unexpected error: {e}",
                    'processing_time': 0,
                    'generated_files': {}
                })
                failed_count += 1
        
        total_time = time.time() - overall_start_time
        
        # Summary
        summary = {
            'success': failed_count == 0,
            'total_files': len(input_files),
            'processed_files': successful_count,
            'failed_files': failed_count,
            'total_processing_time': total_time,
            'results': results
        }
        
        logger.info(f"Batch processing complete:")
        logger.info(f"  Total files: {len(input_files)}")
        logger.info(f"  Successful: {successful_count}")
        logger.info(f"  Failed: {failed_count}")
        logger.info(f"  Total time: {format_duration(total_time)}")
        
        return summary
    
    def generate_batch_summary_report(self, batch_results: Dict[str, Any]) -> Path:
        """
        Generate a summary report for batch processing.
        
        Args:
            batch_results: Results from process_all_files()
            
        Returns:
            Path to generated summary report
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        summary_path = self.output_dir / f"batch_summary_{timestamp}.html"
        
        try:
            # Create simple HTML summary
            html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Batch Processing Summary</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #003f7f; color: white; padding: 20px; border-radius: 5px; }}
        .summary {{ margin: 20px 0; }}
        .results {{ margin: 20px 0; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background: #f2f2f2; }}
        .success {{ color: green; }}
        .error {{ color: red; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>DefensePro Forensics - Batch Processing Summary</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="summary">
        <h2>Processing Summary</h2>
        <ul>
            <li>Total files processed: {batch_results['total_files']}</li>
            <li>Successful: <span class="success">{batch_results['processed_files']}</span></li>
            <li>Failed: <span class="error">{batch_results['failed_files']}</span></li>
            <li>Total processing time: {format_duration(batch_results['total_processing_time'])}</li>
        </ul>
    </div>
    
    <div class="results">
        <h2>File Processing Results</h2>
        <table>
            <thead>
                <tr>
                    <th>File Name</th>
                    <th>Status</th>
                    <th>Processing Time</th>
                    <th>Generated Reports</th>
                    <th>Error Message</th>
                </tr>
            </thead>
            <tbody>
            """
            
            for result in batch_results['results']:
                status = "✅ Success" if result['success'] else "❌ Failed"
                status_class = "success" if result['success'] else "error"
                
                generated_reports = ", ".join([
                    f"{fmt.upper()}: {Path(path).name}" 
                    for fmt, path in result.get('generated_files', {}).items()
                ]) or "None"
                
                error_msg = result.get('error_message', '') or 'N/A'
                
                html_content += f"""
                <tr>
                    <td>{result['file_name']}</td>
                    <td class="{status_class}">{status}</td>
                    <td>{format_duration(result.get('processing_time', 0))}</td>
                    <td>{generated_reports}</td>
                    <td>{error_msg}</td>
                </tr>
                """
            
            html_content += """
            </tbody>
        </table>
    </div>
</body>
</html>
            """
            
            # Write to file
            with open(summary_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"Generated batch summary report: {summary_path}")
            return summary_path
            
        except Exception as e:
            logger.error(f"Failed to generate batch summary report: {e}")
            raise


def create_cli_parser() -> argparse.ArgumentParser:
    """
    Create command-line interface parser.
    
    Returns:
        Configured argument parser
    """
    parser = argparse.ArgumentParser(
        description="DefensePro Forensics Data Analysis & Report Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python analyzer.py
  python analyzer.py --input-dir forensics_input --output-dir reports
  python analyzer.py --format html --verbose
  python analyzer.py --format pdf --input-dir /path/to/files
  
Chart Customization:
  Edit CHART_PREFERENCES in config.py to customize chart types and colors
  See CHART_CONFIGURATION.md for detailed configuration guide
        """
    )
    
    parser.add_argument(
        '--input-dir',
        type=str,
        default='forensics_input',
        help='Directory containing input CSV/ZIP files (default: forensics_input)'
    )
    
    parser.add_argument(
        '--output-dir',
        type=str,
        default='report_files',
        help='Directory for output reports (default: report_files)'
    )
    
    parser.add_argument(
        '--format',
        choices=['html', 'pdf', 'both'],
        default='both',
        help='Output format(s) to generate (default: both - uses OUTPUT_FORMATS from config.py)'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='DefensePro Forensics Analyzer v1.0.0'
    )
    
    return parser


def main():
    """
    Main entry point for the application.
    """
    # Parse command-line arguments
    parser = create_cli_parser()
    args = parser.parse_args()
    
    # Determine output formats
    if args.format == 'both':
        formats = OUTPUT_FORMATS.copy()  # Use config default
    else:
        formats = [args.format]
    
    try:
        # Initialize analyzer
        analyzer = ForensicsAnalyzer(
            input_dir=args.input_dir,
            output_dir=args.output_dir,
            verbose=args.verbose
        )
        
        print("🔍 DefensePro Forensics Data Analysis & Report Generator")
        print("=" * 60)
        
        # Process all files
        batch_results = analyzer.process_all_files(formats)
        
        # Generate batch summary report
        if batch_results['total_files'] > 1:
            summary_path = analyzer.generate_batch_summary_report(batch_results)
            print(f"\n📊 Batch summary report: {summary_path}")
        
        # Print results summary
        print(f"\n✅ Processing complete!")
        print(f"   Total files: {batch_results['total_files']}")
        print(f"   Successful: {batch_results['processed_files']}")
        print(f"   Failed: {batch_results['failed_files']}")
        print(f"   Total time: {format_duration(batch_results['total_processing_time'])}")
        
        # List generated files
        if batch_results['processed_files'] > 0:
            print(f"\n📁 Generated reports:")
            for result in batch_results['results']:
                if result['success']:
                    for fmt, path in result['generated_files'].items():
                        print(f"   {fmt.upper()}: {path}")
        
        # Exit with appropriate code
        sys.exit(0 if batch_results['success'] else 1)
        
    except KeyboardInterrupt:
        print("\n⚠️  Processing interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        logging.exception("Fatal error in main()")
        sys.exit(1)


if __name__ == "__main__":
    main()