# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import re
import os
import subprocess


from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.exceptions import CuckooProcessingError

class Volaility(Processing):
    """Use volaility to do analysis on the memory dump"""
    def init(self):
        self.volpath = '/home/cuckoouser/volatility/vol.py'
        self.memdump = self.memory_path
        self.volprofile = "WinXPSP3x86"
        
    def _runVolModule(self, vol_mod):
        results = 'NA'
        
        results = subprocess.check_output(['python', self.volpath, vol_mod, 
                                           '-f', self.memdump, '--profile', self.volprofile])
        results = results.split('\n')
        return results
    
    def run(self):
        """Run volatility plugins on memory dump.
        @return: list of volaility commands.
        """
        self.key = "volatility"
        
        modules_to_run = ['psscan', 'psxview', 'malfind', 'cmdscan']
        
        volatility = dict()
        
        self.init()
        
        if os.path.exists(self.memdump):
            for module in modules_to_run:
                volatility[module] = self._runVolModule(module)
            
        return volatility
