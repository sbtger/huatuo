# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Retain only actual completed flows; never allocate synthetic pressure."""
import os
from pathlib import Path
from mitmproxy import ctx


class Retention:
    def __init__(self):
        self.flows=[]

    def load(self,loader):
        loader.add_option('business_control',str,'','flow retention control file')

    def response(self,flow):
        budget=int(Path(ctx.options.business_control).read_text())
        if flow.request.path=='/large' and budget:self.flows.append(flow)
        if len(self.flows)>budget:del self.flows[:len(self.flows)-budget]


addons=[Retention()]
