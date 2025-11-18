class CachingDict:
    def __init__(self, value_factory, key_transform=lambda x: x):
        super().__init__()
        self.d = dict()
        self.value_factory = value_factory
        self.key_transform = key_transform

    def __getitem__(self, prekey):
        key = self.key_transform(prekey)
        value = self.d.get(key, None)
        if value is None:
            value = self.d[key] = self.value_factory(prekey)
        return value
