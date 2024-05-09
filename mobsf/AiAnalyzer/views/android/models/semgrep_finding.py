class AnalysisResult:
    def __init__(self, data):
        self.check_id = data.get('check_id')
        self.path = data.get('path')
        self.extra = Extra(data.get('extra'))

class Extra:
    def __init__(self, data):
        self.engine_kind = data.get('engine_kind')
        self.fingerprint = data.get('fingerprint')
        self.is_ignored = data.get('is_ignored')
        self.lines = data.get('lines')
        self.message = data.get('message')
        self.metadata = Metadata(data.get('metadata'))
        self.severity = data.get('severity')
        self.validation_state = data.get('validation_state')

class Metadata:
    def __init__(self, data):
        self.category = data.get('category')
        self.owasp_mobile = data.get('owasp-mobile')
        self.llmchain = data.get('llmchain')
        self.technology = data.get('technology')
