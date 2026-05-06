"""
Enigma — Root pytest configuration.
Adds all phase directories to sys.path so tests can import modules cleanly.
"""
import sys
import os

# Add each phase directory to sys.path for clean imports
_phases_dir = os.path.join(os.path.dirname(__file__), 'phases')
for phase_dir in sorted(os.listdir(_phases_dir)):
    phase_path = os.path.join(_phases_dir, phase_dir)
    if os.path.isdir(phase_path) and not phase_dir.startswith('_'):
        if phase_path not in sys.path:
            sys.path.insert(0, phase_path)
