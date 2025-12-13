"""
HTML Reporter for QWED Test Results
Interactive dashboard with visualization
"""

from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any


class HTMLReporter:
    """Generate HTML dashboard from test results"""
    
    def __init__(self, output_dir: str = "./test_results"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_report(self, summary: Dict[str, Any], results: List[Dict[str, Any]]) -> str:
        """
        Generate interactive HTML dashboard
        
        Args:
            summary: Test summary statistics
            results: List of individual test results
        
        Returns:
            Path to generated report file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"qwed_test_report_{timestamp}.html"
        
        html_content = self._build_html(summary, results)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return str(output_file)
    
    def _build_html(self, summary: Dict[str, Any], results: List[Dict[str, Any]]) -> str:
        """Build HTML content"""
        total = summary.get('total_tests', 0)
        passed = summary.get('passed', 0)
        failed = summary.get('failed', 0)
        pass_rate = summary.get('pass_rate', 0)
        duration = summary.get('duration_seconds', 0)
        
        # Determine overall status
        if pass_rate >= 90:
            status_color = "#4CAF50"  # Green
            status_text = "EXCELLENT"
        elif pass_rate >= 75:
            status_color = "#8BC34A"  # Light green
            status_text = "GOOD"
        elif pass_rate >= 50:
            status_color = "#FF9800"  # Orange
            status_text = "NEEDS IMPROVEMENT"
        else:
            status_color = "#F44336"  # Red
            status_text = "CRITICAL ISSUES"
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>QWED Test Report - {datetime.now().strftime('%Y-%m-%d')}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .header .subtitle {{
            opacity: 0.9;
            font-size: 1.1em;
        }}
        
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }}
        
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            text-align: center;
        }}
        
        .stat-card .number {{
            font-size: 2.5em;
            font-weight: bold;
            margin: 10px 0;
        }}
        
        .stat-card .label {{
            color: #666;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 1px;
        }}
        
        .status-badge {{
            display: inline-block;
            padding: 10px 20px;
            border-radius: 25px;
            background: {status_color};
            color: white;
            font-weight: bold;
            margin-top: 10px;
        }}
        
        .content {{
            padding: 30px;
        }}
        
        .section {{
            margin-bottom: 40px;
        }}
        
        .section h2 {{
            color: #667eea;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #667eea;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }}
        
        th {{
            background: #667eea;
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
        }}
        
        td {{
            padding: 12px 15px;
            border-bottom: 1px solid #eee;
        }}
        
        tr:hover {{
            background: #f8f9fa;
        }}
        
        .pass-rate {{
            font-weight: bold;
        }}
        
        .pass-rate.excellent {{ color: #4CAF50; }}
        .pass-rate.good {{ color: #8BC34A; }}
        .pass-rate.warning {{ color: #FF9800; }}
        .pass-rate.critical {{ color: #F44336; }}
        
        .test-item {{
            background: white;
            padding: 15px;
            margin-bottom: 10px;
            border-left: 4px solid #667eea;
            border-radius: 4px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        
        .test-item.failed {{
            border-left-color: #F44336;
        }}
        
        .test-item.passed {{
            border-left-color: #4CAF50;
        }}
        
        .test-item h3 {{
            color: #333;
            margin-bottom: 8px;
        }}
        
        .test-meta {{
            color: #666;
            font-size: 0.9em;
        }}
        
        .test-meta span {{
            margin-right: 15px;
        }}
        
        .error-message {{
            background: #ffebee;
            color: #c62828;
            padding: 10px;
            border-radius: 4px;
            margin-top: 10px;
            font-family: monospace;
            font-size: 0.9em;
        }}
        
        .footer {{
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ QWED Comprehensive Test Audit</h1>
            <p class="subtitle">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <div class="status-badge">{status_text}</div>
        </div>
        
        <div class="summary">
            <div class="stat-card">
                <div class="label">Total Tests</div>
                <div class="number">{total}</div>
            </div>
            <div class="stat-card">
                <div class="label">Passed</div>
                <div class="number" style="color: #4CAF50">{passed}</div>
            </div>
            <div class="stat-card">
                <div class="label">Failed</div>
                <div class="number" style="color: #F44336">{failed}</div>
            </div>
            <div class="stat-card">
                <div class="label">Pass Rate</div>
                <div class="number">{pass_rate:.1f}%</div>
            </div>
            <div class="stat-card">
                <div class="label">Duration</div>
                <div class="number">{duration:.1f}s</div>
            </div>
        </div>
        
        <div class="content">
"""
        
        # By Priority Table
        by_priority = summary.get('by_priority', {})
        if by_priority:
            html += """
            <div class="section">
                <h2>📊 Results by Priority</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Total</th>
                            <th>Passed</th>
                            <th>Failed</th>
                            <th>Pass Rate</th>
                        </tr>
                    </thead>
                    <tbody>
"""
            for priority in ['critical', 'high', 'medium']:
                if priority in by_priority:
                    stats = by_priority[priority]
                    total_p = stats.get('total', 0)
                    passed_p = stats.get('passed', 0)
                    failed_p = total_p - passed_p
                    rate_p = stats.get('pass_rate', 0)
                    
                    rate_class = 'excellent' if rate_p >= 90 else 'good' if rate_p >= 75 else 'warning' if rate_p >= 50 else 'critical'
                    
                    html += f"""
                        <tr>
                            <td><strong>{priority.upper()}</strong></td>
                            <td>{total_p}</td>
                            <td>{passed_p}</td>
                            <td>{failed_p}</td>
                            <td class="pass-rate {rate_class}">{rate_p:.1f}%</td>
                        </tr>
"""
            html += """
                    </tbody>
                </table>
            </div>
"""
        
        # By Engine Table
        by_engine = summary.get('by_engine', {})
        if by_engine:
            html += """
            <div class="section">
                <h2>🔧 Results by Engine</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Engine</th>
                            <th>Total</th>
                            <th>Passed</th>
                            <th>Failed</th>
                            <th>Pass Rate</th>
                        </tr>
                    </thead>
                    <tbody>
"""
            for engine, stats in sorted(by_engine.items()):
                total_e = stats.get('total', 0)
                passed_e = stats.get('passed', 0)
                failed_e = total_e - passed_e
                rate_e = stats.get('pass_rate', 0)
                
                rate_class = 'excellent' if rate_e >= 80 else 'good' if rate_e >= 60 else 'warning' if rate_e >= 40 else 'critical'
                
                html += f"""
                    <tr>
                        <td><strong>{engine.upper()}</strong></td>
                        <td>{total_e}</td>
                        <td>{passed_e}</td>
                        <td>{failed_e}</td>
                        <td class="pass-rate {rate_class}">{rate_e:.1f}%</td>
                    </tr>
"""
            html += """
                    </tbody>
                </table>
            </div>
"""
        
        # Failed Tests
        failures = [r for r in results if not r.get("passed", False)]
        if failures:
            html += f"""
            <div class="section">
                <h2>❌ Failed Tests ({len(failures)})</h2>
"""
            for fail in failures:
                test_name = fail.get('test_name', 'Unknown Test')
                engine = fail.get('engine', 'N/A')
                priority = fail.get('priority', 'N/A')
                test_id = fail.get('test_id', 'N/A')
                error = fail.get('error', '')
                
                html += f"""
                <div class="test-item failed">
                    <h3>{test_name}</h3>
                    <div class="test-meta">
                        <span><strong>Engine:</strong> {engine}</span>
                        <span><strong>Priority:</strong> {priority}</span>
                        <span><strong>ID:</strong> {test_id}</span>
                    </div>
"""
                if error:
                    html += f"""
                    <div class="error-message">{error}</div>
"""
                html += """
                </div>
"""
            html += """
            </div>
"""
        
        # Footer
        html += """
        </div>
        
        <div class="footer">
            <p>Generated by <strong>QWED Advanced Testing Framework</strong></p>
            <p>🛡️ Systematic Testing · No Shortcuts · Production Ready</p>
        </div>
    </div>
</body>
</html>
"""
        
        return html
