class CachingDict(dict):
    def __init__(self, default_factory):
        super().__init__()
        self.default_factory = default_factory

    def __missing__(self, key):
        value = self.default_factory(key)
        self[key] = value
        return value
