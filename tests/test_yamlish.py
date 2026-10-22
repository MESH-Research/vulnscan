from vulnscan.parsers.yamlish import load_yamlish


def test_empty_and_comment_only_text_is_none():
    assert load_yamlish("") is None
    assert load_yamlish("# just a comment\n\n") is None


def test_nested_mappings_scalars_and_quotes():
    text = (
        "version: '3.8'\n"
        "services:\n"
        "  web:\n"
        '    image: "nginx:1.25"   # inline comment\n'
        "    restart: always\n"
        "  db:\n"
        "    image: postgres:16 # trailing\n"
        "    environment:\n"
        "      TZ: Europe/London\n"
        "      URL: http://example.com/#anchor\n"
        "x-empty:\n"
    )
    assert load_yamlish(text) == {
        "version": "3.8",
        "services": {
            "web": {"image": "nginx:1.25", "restart": "always"},
            "db": {
                "image": "postgres:16",
                "environment": {"TZ": "Europe/London", "URL": "http://example.com/#anchor"},
            },
        },
        "x-empty": None,
    }


def test_lists_of_scalars_and_mappings():
    text = (
        "services:\n"
        "  - postgres:16\n"
        "  - name: redis:7\n"
        "    alias: cache\n"
        '  - "quoted:1"\n'
        "steps:\n"
        "- uses: actions/checkout@v4\n"
        "- name: Build\n"
        "  run: make\n"
        "  with:\n"
        "    depth: 1\n"
    )
    assert load_yamlish(text) == {
        "services": ["postgres:16", {"name": "redis:7", "alias": "cache"}, "quoted:1"],
        "steps": [
            {"uses": "actions/checkout@v4"},
            {"name": "Build", "run": "make", "with": {"depth": "1"}},
        ],
    }


def test_list_at_same_indent_as_its_key():
    text = "services:\n- postgres:16\n- mysql:8\nimage: php:8.2\n"
    assert load_yamlish(text) == {"services": ["postgres:16", "mysql:8"], "image": "php:8.2"}


def test_block_scalars_flow_collections_and_anchors_do_not_break_structure():
    text = (
        "a:\n"
        "  script: |\n"
        "    echo one\n"
        "    echo two: three\n"
        "  after: ok\n"
        "b: {image: inline, other: 1}\n"
        "c: [one, two]\n"
        "d: &anchor\n"
        "  image: php:8.2\n"
        "e:\n"
        "  <<: *anchor\n"
        "  extra: yes\n"
        "f: *anchor\n"
    )
    data = load_yamlish(text)
    assert data["a"]["after"] == "ok"
    assert isinstance(data["a"]["script"], str)
    assert isinstance(data["b"], str) and data["b"].startswith("{")
    assert isinstance(data["c"], str) and data["c"].startswith("[")
    assert data["d"] == {"image": "php:8.2"}
    assert data["e"]["extra"] == "yes"
    assert isinstance(data["f"], str)


def test_top_level_list_and_tabs_and_crlf():
    assert load_yamlish("- a\n- b\n") == ["a", "b"]
    assert load_yamlish("jobs:\r\n  build:\r\n    image: x:1\r\n") == {
        "jobs": {"build": {"image": "x:1"}}
    }


def test_colon_inside_values_and_urls():
    text = "image: registry.example.com:5000/app:1.0\nurl: https://example.com:8443/x\n"
    assert load_yamlish(text) == {
        "image": "registry.example.com:5000/app:1.0",
        "url": "https://example.com:8443/x",
    }


def test_last_duplicate_key_wins_and_keys_may_be_quoted():
    text = '"image": a:1\nimage: b:2\n'
    assert load_yamlish(text) == {"image": "b:2"}
