"""Explicit installed choices must not be mistaken for implicit defaults."""
import pytest
import yaml

@pytest.mark.parametrize(('section', 'key', 'value'), [
    ('display', 'background_process_notifications', 'all'),
    ('delegation', 'max_iterations', 50),
])
def test_upgrade_preserves_explicit_supported_choice(tmp_path, monkeypatch, section, key, value):
    from hermes_cli import config
    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    path = tmp_path / 'config.yaml'
    path.write_text(yaml.safe_dump({'_config_version': 34, section: {key: value}}))
    config.migrate_config(interactive=False, quiet=True)
    assert config.load_config_readonly()[section][key] == value
    assert yaml.safe_load(path.read_text())[section][key] == value
