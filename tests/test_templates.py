# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import re
from html import unescape
from pathlib import Path

from jinja2 import ChoiceLoader, DictLoader, Environment, FileSystemLoader


INLINE_EXPRESSION = re.compile(r"\{\{\s*(.*?)\s*\}\}")
ONCLICK_ATTRIBUTE = re.compile(r'onclick="([^"]*)"')


def test_widget_templates_compile_with_jinja() -> None:
    environment = Environment(loader=FileSystemLoader("templates"), autoescape=True)
    for template in Path("templates").glob("*.html"):
        environment.get_template(template.name)


def test_widget_templates_extend_before_emitting_content() -> None:
    for template in Path("templates").glob("*.html"):
        assert (
            template.read_text()
            .lstrip()
            .startswith("{% extends 'widgets/widget_template.html' %}")
        ), f"{template} emits content before extending the SOAR widget"


def test_device_scroll_renders_parent_before_license_comment() -> None:
    environment = Environment(
        loader=ChoiceLoader(
            [
                FileSystemLoader("templates"),
                DictLoader(
                    {
                        "widgets/widget_template.html": (
                            "<section>{% block widget_content %}{% endblock %}</section>"
                        )
                    }
                ),
            ]
        ),
        autoescape=True,
    )
    rendered = environment.get_template("crowdstrike_get_device_scroll.html").render(
        results=[]
    )
    assert rendered.startswith("<section>")


def test_widget_javascript_values_are_safe_in_html_attributes() -> None:
    failures = []
    for template in Path("templates").glob("*.html"):
        for line_number, line in enumerate(template.read_text().splitlines(), 1):
            onclick = ONCLICK_ATTRIBUTE.search(line)
            if onclick is None:
                continue
            for expression in INLINE_EXPRESSION.findall(onclick.group(1)):
                if expression.strip() in {"container", "container.id"}:
                    continue
                if not expression.strip().endswith("|string|tojson|forceescape"):
                    failures.append(f"{template}:{line_number}: {expression}")

    assert failures == []


def test_widget_value_survives_json_and_html_attribute_escaping() -> None:
    value = "quote' \" <script> & newline\n"
    environment = Environment(autoescape=True)
    rendered = environment.from_string(
        "onclick=\"context_menu(this, [{'value': {{ value|string|tojson|forceescape }} }]);\""
    ).render(value=value)

    assert rendered.count('"') == 2
    assert "&#34;" in rendered
    assert "\\u003cscript\\u003e" in rendered
    onclick = unescape(rendered[len('onclick="') : -1])
    match = re.search(r"'value': (\"(?:\\.|[^\"])*\")", onclick)
    assert match is not None
    assert json.loads(match.group(1)) == value
