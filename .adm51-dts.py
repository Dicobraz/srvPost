# -*- coding: utf-8 -*-
"""Финальная сборка console/src/api/schema.d.ts для ADM-51 по правилам openapi-typescript
(уточнены диффом CI): медиа-строки ответов 20 пробелов, @description у параметров и свойств,
@enum {string} у перечислений, комментарий тела запроса."""
import json
import subprocess

SPEC = 'console/src/api/openapi.json'
OUT = 'console/src/api/schema.d.ts'
NL = chr(10)

spec = json.load(open(SPEC, encoding='utf-8'))

MY_PATHS = ['/api/v1/risk/signals', '/api/v1/risk/signals/{id}',
            '/api/v1/risk/thresholds', '/api/v1/risk/packages',
            '/api/v1/risk/packages/{version}/activate', '/api/v1/risk/packages/{version}/rollback',
            '/api/v1/risk/sources', '/api/v1/risk/sources/{id}',
            '/api/v1/risk/sources/{id}/import', '/api/v1/risk/sources/{id}/refresh',
            '/api/v1/risk/sources/{id}/usage', '/api/v1/orgs/{org}/risk/signals',
            '/api/v1/orgs/{org}/risk/signals/{id}', '/api/v1/orgs/{org}/risk/thresholds',
            '/api/v1/orgs/{org}/risk/hits']
MY_SCHEMAS = ['OriginSchema', 'FieldSchema', 'DetectorSchema', 'RiskActionSchema', 'ModeSchema',
              'RiskLevelSchema', 'ThresholdsSchema', 'PolicyViolationSchema', 'UpdateReportSchema',
              'PackageStateSchema', 'TierSchema', 'TiOriginSchema', 'SourceKindSchema',
              'FeedFormatSchema', 'StaleActionSchema', 'LicenseSchema', 'TenantsSchema',
              'SecretRefSchema', 'HttpAuthSchema', 'TlpSchema', 'SignalView', 'SignalBody',
              'SignalsView', 'ThresholdsBody', 'ThresholdsView', 'PackageEntryView',
              'PackagesView', 'PackageReportView', 'TiSourceBody', 'NewTiSourceBody',
              'TiSourceView', 'SourcesView', 'ListVersionView', 'UsageTotalView', 'UsageView',
              'HitView', 'HitsView', 'RiskProblem']
METHODS = ['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace']


def comment_lines(text, indent):
    lines = text.split(NL)
    if len(lines) == 1:
        return [indent + '/** ' + text + ' */']
    out = [indent + '/**']
    for i, l in enumerate(lines):
        head = '* ' if i == 0 else '*     '
        out.append(indent + ' ' + head + l)
    out.append(indent + ' */')
    return out


def schema_name(ref):
    return ref.rsplit('/', 1)[-1]


def nullable(schema):
    if 'oneOf' in schema and any(v.get('type') == 'null' for v in schema['oneOf']):
        return True
    t = schema.get('type')
    return isinstance(t, list) and 'null' in t


def ts_type(s, indent):
    if '$ref' in s:
        return 'components["schemas"]["' + schema_name(s['$ref']) + '"]'
    if 'oneOf' in s:
        parts = []
        for v in s['oneOf']:
            if v.get('type') == 'null':
                parts.append('null')
            elif '$ref' in v:
                parts.append(ts_type(v, indent))
            elif 'enum' in v:
                parts.append(' | '.join(json.dumps(x) for x in v['enum']))
            else:
                parts.append(None)
        if None not in parts:
            return ' | '.join(parts)
        raise ValueError('объектный вариант внутри свойства')
    if 'properties' in s and 'enum' not in s:
        inner = indent + '    '
        out = ['{']
        for pname in s['properties']:
            p = s['properties'][pname]
            if p.get('description'):
                out += comment_lines('@description ' + p['description'], inner)
            out.append(inner + pname + ': ' + ts_type(p, inner) + ';')
        out.append(indent + '}')
        return NL.join(out)
    t = s.get('type')
    if t == 'string':
        return 'string'
    if t in ('integer', 'number'):
        return 'number'
    if t == 'boolean':
        return 'boolean'
    if t == 'array':
        return ts_type(s['items'], indent) + '[]'
    if isinstance(t, list):
        base = dict(s)
        base['type'] = t[0]
        return ts_type(base, indent) + ' | null'
    raise ValueError(str(s)[:120])


def prop_desc(schema):
    if 'description' in schema:
        return schema['description']
    if 'oneOf' in schema:
        for v in schema['oneOf']:
            if 'description' in v:
                return v['description']
    return None


def prop_lines(name, schema, required, indent):
    lines = []
    fmt = schema.get('format')
    desc = prop_desc(schema)
    if fmt and desc:
        lines.append(indent + '/**')
        lines.append(indent + ' ' + ' * Format: ' + fmt)
        for i, d in enumerate(desc.split(NL)):
            head = '* @description ' if i == 0 else '*     '
            lines.append(indent + ' ' + head + d)
        lines.append(indent + ' ' + ' */')
    elif desc:
        lines += comment_lines('@description ' + desc, indent)
    elif fmt:
        lines.append(indent + '/** Format: ' + fmt + ' */')
    lines.append(indent + name + ('' if required else '?') + ': ' + ts_type(schema, indent) + ';')
    return lines


def schema_block(name, sch):
    out = []
    desc = sch.get('description')
    if 'enum' in sch:
        if desc:
            dlines = desc.split(NL)
            block = ['        /**', '         * @description ' + dlines[0]]
            block += ['         *     ' + d for d in dlines[1:]]
            block += ['         * @enum {string}', '         */']
            out += block
        out.append('        ' + name + ': ' +
                   ' | '.join(json.dumps(x) for x in sch['enum']) + ';')
        return out
    if 'oneOf' in sch:
        if desc:
            out += comment_lines('@description ' + desc, '        ')
        simple, objects = [], []
        for v in sch['oneOf']:
            if 'enum' in v:
                simple.append(' | '.join(json.dumps(x) for x in v['enum']))
            elif '$ref' in v:
                simple.append(ts_type(v, '        '))
            else:
                objects.append(v)
        first = '        ' + name + ': ' + (' | '.join(simple) + ' | ' if simple else '')
        if not objects:
            out.append(first.rstrip() + ';')
            return out
        out.append(first + '{')
        for i, v in enumerate(objects):
            if i > 0:
                out.append('        } | {')
            for pname in v.get('properties', {}):
                p = v['properties'][pname]
                if p.get('description'):
                    out += comment_lines('@description ' + p['description'], '            ')
                out.append('            ' + pname + ': ' + ts_type(p, '            ') + ';')
        out.append('        };')
        return out
    if desc:
        out += comment_lines('@description ' + desc, '        ')
    out.append('        ' + name + ': {')
    required = set(sch.get('required', []))
    for pname in sch.get('properties', {}):
        p = sch['properties'][pname]
        req = pname in required and not nullable(p)
        out += prop_lines(pname, p, req, '            ')
    out.append('        };')
    return out


def param_prop_lines(p, indent):
    out = []
    if p.get('description'):
        out += comment_lines('@description ' + p['description'], indent)
    out.append(indent + p['name'] + ('' if p.get('required') else '?') + ': ' +
               ts_type(p['schema'], indent) + ';')
    return out


def op_block(fn, op):
    out = ['    ' + fn + ': {', '        parameters: {']
    query = [p for p in op.get('parameters', []) if p['in'] == 'query']
    path = [p for p in op.get('parameters', []) if p['in'] == 'path']
    if query:
        out.append('            query?: {')
        for p in query:
            out += param_prop_lines(p, '                ')
        out.append('            };')
    else:
        out.append('            query?: never;')
    out.append('            header?: never;')
    if path:
        out.append('            path: {')
        for p in path:
            out += param_prop_lines(p, '                ')
        out.append('            };')
    else:
        out.append('            path?: never;')
    out.append('            cookie?: never;')
    out.append('        };')
    rb = op.get('requestBody')
    if rb:
        if rb.get('description'):
            out += comment_lines('@description ' + rb['description'], '        ')
        out.append('        requestBody: {')
        out.append('            content: {')
        for ct, c in rb['content'].items():
            if ct == 'application/octet-stream':
                out.append('                "application/octet-stream": string;')
            else:
                out.append('                "' + ct + '": ' +
                           ts_type(c['schema'], '                ') + ';')
        out.append('            };')
        out.append('        };')
    else:
        out.append('        requestBody?: never;')
    out.append('        responses: {')
    for code in sorted(op['responses'], key=int):
        r = op['responses'][code]
        if r.get('description'):
            out.append('            /** @description ' + r['description'] + ' */')
        out.append('            ' + code + ': {')
        out.append('                headers: {')
        out.append('                    [name: string]: unknown;')
        out.append('                };')
        content = r.get('content', {})
        if content:
            out.append('                content: {')
            for ct, c in content.items():
                out.append('                    "' + ct + '": components["schemas"]["' +
                           schema_name(c['schema']['$ref']) + '"];')
            out.append('                };')
        else:
            out.append('                content?: never;')
        out.append('            };')
    out.append('        };')
    out.append('    };')
    return out


def path_block(p, item):
    out = ['    "' + p + '": {', '        parameters: {',
           '            query?: never;', '            header?: never;',
           '            path?: never;', '            cookie?: never;', '        };']
    for m in METHODS:
        if m in item:
            if item[m].get('summary'):
                out += comment_lines(item[m]['summary'], '        ')
            out.append('        ' + m + ': operations["' + item[m]['operationId'] + '"];')
        else:
            out.append('        ' + m + '?: never;')
    out.append('    };')
    return out


paths_ts = []
ops_ts = []
for p in MY_PATHS:
    item = spec['paths'][p]
    paths_ts += path_block(p, item)
    for m in METHODS:
        if m in item:
            ops_ts += op_block(item[m]['operationId'], item[m])

schemas_ts = []
for name in MY_SCHEMAS:
    schemas_ts += schema_block(name, spec['components']['schemas'][name])

# база — схема консоли из origin/main (до ADM-51)
base = subprocess.run(['git', 'show', 'origin/main:console/src/api/schema.d.ts'],
                      capture_output=True).stdout.decode('utf-8')
lines = base.split(NL)

idx_close = next(i for i, l in enumerate(lines) if l == '}')
assert lines[idx_close + 1].startswith('export type webhooks'), lines[idx_close + 1]
for l in reversed(paths_ts):
    lines.insert(idx_close, l)

idx_resp = next(i for i, l in enumerate(lines) if l == '    responses: never;')
assert lines[idx_resp - 1] == '    };', lines[idx_resp - 1]
for l in reversed(schemas_ts):
    lines.insert(idx_resp - 1, l)

text = NL.join(lines)
body = text.rstrip(NL)
assert body.endswith('}'), repr(body[-4:])
inner = body[:-1].rstrip(NL)
assert inner.endswith('};'), repr(inner[-6:])
text = inner + NL + NL + NL.join(ops_ts) + NL + '}'

open(OUT, 'w', encoding='utf-8', newline=NL).write(text)
print('d.ts rebuilt from origin/main: paths', len(paths_ts), 'schemas', len(schemas_ts),
      'ops', len(ops_ts))
