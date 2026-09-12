const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function setup() {
    const html = fs.readFileSync(path.join(__dirname, '../templates/index.html'), 'utf8');
    const start = html.indexOf('        let evaluationRequestId = 0;');
    const end = html.lastIndexOf('    </script>');
    assert.ok(start >= 0 && end > start, 'Evaluation script must be present');
    assert.match(html, /id="analyzeBtn"/);
    const nodes = new Map();
    const calls = [];
    const element = id => {
        if (!nodes.has(id)) nodes.set(id, {
            style: {}, innerText: '', value: '', events: {},
            addEventListener(event, handler) { this.events[event] = handler; }
        });
        return nodes.get(id);
    };
    const context = vm.createContext({
        document: { getElementById: element }, console: { error() {} },
        clearRateLimitError() {}, showRateLimitError() {},
        fetch(url, options) {
            return new Promise((resolve, reject) => calls.push({ url, options, resolve, reject }));
        }
    });
    vm.runInContext(html.slice(start, end), context);
    return { context, calls, element };
}

const response = score => ({
    ok: true, status: 200,
    json: async () => ({ score, hibp: { available: true, found: false } })
});

test('Typing sends nothing; Analyze sends the current input', () => {
    const { calls, element } = setup();
    const input = element('passwordInput');
    input.value = 'dummy-input-only';
    input.events.input({ target: input });
    assert.equal(calls.length, 0);
    element('analyzeBtn').events.click();
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, '/api/evaluate');
    assert.equal(JSON.parse(calls[0].options.body).password, input.value);
    calls[0].resolve(response(1));
});

test('Older responses cannot overwrite newer results', async () => {
    const { context, calls, element } = setup();
    const older = context.evaluatePassword('old-dummy');
    const newer = context.evaluatePassword('new-dummy');
    calls[1].resolve(response(0));
    await newer;
    calls[0].resolve(response(4));
    await older;
    assert.equal(element('scoreVal').innerText, '0 / 4');
});

test('Editing invalidates an outstanding response', async () => {
    const { context, calls, element } = setup();
    const pending = context.evaluatePassword('dummy');
    const input = element('passwordInput');
    input.value = 'changed';
    input.events.input({ target: input });
    calls[0].resolve(response(4));
    await pending;
    assert.equal(calls.length, 1);
    assert.equal(element('scoreVal').innerText, '- / 4');
    assert.equal(element('hibpVal').innerText, '-');
});

test('Failed evaluation does not retain a previous good score', async () => {
    const { context, calls, element } = setup();
    const first = context.evaluatePassword('first-dummy');
    calls[0].resolve(response(4));
    await first;
    const second = context.evaluatePassword('second-dummy');
    assert.equal(element('scoreVal').innerText, '- / 4');
    calls[1].reject(new Error('Simulated network failure'));
    await second;
    assert.equal(element('hibpVal').innerText, 'Evaluation unavailable');
    assert.equal(element('scoreVal').innerText, '- / 4');
});
