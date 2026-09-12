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

    const nodes = new Map();
    const calls = [];

    const element = id => {
        if (!nodes.has(id)) nodes.set(id, {
            style: {},
            innerText: '',
            value: '',
            events: {},
            addEventListener(event, handler) {
                this.events[event] = handler;
            }
        });
        return nodes.get(id);
    };

    const context = vm.createContext({
        document: { getElementById: element },
        console: { error() {} },
        clearRateLimitError() {},
        showRateLimitError() {},
        zxcvbn: password => ({
            score: password.startsWith('old') ? 4 : 1,
            guesses: 1024,
            crack_times_display: {},
        }),
        sha1: password => password.startsWith('old')
            ? `ABCDE${'A'.repeat(35)}`
            : `12345${'B'.repeat(35)}`,
        fetch(url, options) {
            return new Promise((resolve, reject) => {
                calls.push({ url, options, resolve, reject });
            });
        },
    });

    vm.runInContext(html.slice(start, end), context);
    return { context, calls, element };
}

const response = body => ({
    ok: true,
    status: 200,
    text: async () => body,
    json: async () => ({}),
});

test('Typing sends no request; Analyze sends only a five-character prefix', () => {
    const { calls, element } = setup();
    const input = element('passwordInput');

    input.value = 'dummy-input-only';
    input.events.input({ target: input });
    assert.equal(calls.length, 0);

    element('analyzeBtn').events.click();
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, '/api/hibp/12345');
    assert.equal(calls[0].options.method, 'GET');
    assert.equal('body' in calls[0].options, false);
    assert.equal(JSON.stringify(calls[0]).includes(input.value), false);

    calls[0].resolve(response(''));
});

test('The full suffix is compared locally', async () => {
    const { context, calls, element } = setup();
    const pending = context.evaluatePassword('dummy');

    calls[0].resolve(
        response(`${'B'.repeat(35)}:27\r\n${'0'.repeat(35)}:0\r\n`)
    );
    await pending;

    assert.equal(element('hibpVal').innerText, 'Found in 27 breaches!');
});

test('Older HIBP responses cannot overwrite newer results', async () => {
    const { context, calls, element } = setup();
    const older = context.evaluatePassword('old-dummy');
    const newer = context.evaluatePassword('new-dummy');

    calls[1].resolve(response(''));
    await newer;

    calls[0].resolve(response(`${'A'.repeat(35)}:99`));
    await older;

    assert.equal(element('scoreVal').innerText, '1 / 4');
    assert.equal(element('hibpVal').innerText, 'No breaches found');
});

test('Editing invalidates an outstanding HIBP response', async () => {
    const { context, calls, element } = setup();
    const pending = context.evaluatePassword('dummy');
    const input = element('passwordInput');

    input.value = 'changed';
    input.events.input({ target: input });
    calls[0].resolve(response(`${'B'.repeat(35)}:99`));
    await pending;

    assert.equal(calls.length, 1);
    assert.equal(element('scoreVal').innerText, '- / 4');
    assert.equal(element('hibpVal').innerText, '-');
});

test('HIBP failure preserves local analysis and reports unavailable', async () => {
    const { context, calls, element } = setup();
    const pending = context.evaluatePassword('dummy');

    calls[0].reject(new Error('Simulated network failure'));
    await pending;

    assert.equal(element('scoreVal').innerText, '1 / 4');
    assert.equal(element('entropyVal').innerText, '10 bits');
    assert.equal(element('hibpVal').innerText, 'HIBP check unavailable');
});
