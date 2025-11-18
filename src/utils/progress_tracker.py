"""
Progress tracking utilities for analysis phases.
"""

import time
from typing import Optional


class ProgressTracker:
    """Tracks progress of analysis phases with timing information."""
    
    def __init__(self, quiet: bool = False):
        self.quiet = quiet
        self.current_step = None
        self.step_start_time = None
        self.total_start_time = time.time()
        self.steps_completed = []
    
    def start_step(self, step_name: str, description: str):
        """Start a new analysis step."""
        self.current_step = step_name
        self.step_start_time = time.time()
        
        if not self.quiet:
            print(f"[{self._get_timestamp()}] Starting {step_name}: {description}")
    
    def finish_step(self, step_name: str, result_description: str):
        """Finish the current analysis step."""
        if self.step_start_time:
            duration = time.time() - self.step_start_time
            self.steps_completed.append({
                'step': step_name,
                'duration': duration,
                'result': result_description
            })
            
            if not self.quiet:
                print(f"[{self._get_timestamp()}] Completed {step_name} in {duration:.2f}s - {result_description}")
        
        self.current_step = None
        self.step_start_time = None
    
    def get_total_time(self) -> float:
        """Get total analysis time."""
        return time.time() - self.total_start_time
    
    def get_step_summary(self) -> str:
        """Get summary of completed steps."""
        if not self.steps_completed:
            return "No steps completed"
        
        summary = []
        for step in self.steps_completed:
            summary.append(f"  {step['step']}: {step['duration']:.2f}s - {step['result']}")
        
        return "\n".join(summary)
    
    def _get_timestamp(self) -> str:
        """Get current timestamp for logging."""
        return time.strftime("%H:%M:%S")