class Advisory:
    __slots__ = (
        'html', 'state', 'cvss', 'attention', 'vendor', 'equipment',
        'vulnerabilities',
    )

    def __init__(self, html):
        self.html = html
        self.state = dict(
            cvss=False,
            attention=False,
            vendor=False,
            equipment=False,
            vulnerabilities=False,
        )
        self.cvss = None
        self.attention = None
        self.vendor = None
        self.equipment = None
        self.vulnerabilities = None

    def set(self, **kwargs):
        assert len(kwargs.keys()) == 2
        done = kwargs.pop('done', False)
        key = list(kwargs.keys())[0]
        value = kwargs[key]
        self.state[key] = done
        setattr(self, key, value)
