const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function setup(randomValues = [0, 1, 2, 3, 4, 5]) {
    const html = fs.readFileSync(
        path.join(__dirname, '../templates/index.html'),
        'utf8'
    );
    const start = html.indexOf('        const wordlistCache = new Map();');
    const end = html.indexOf('        async function copyText', start);

    assert.ok(start >= 0 && end > start, 'Generator script must be present');

    const nodes = new Map();
    const requests = [];
    const words = ['alpha', 'bravo', 'charlie'];
    let randomIndex = 0;

    function makeElement() {
        return {
            style: {},
            value: '',
            innerText: '',
            events: {},
            children: [],
            addEventListener(event, handler) {
                this.events[event] = handler;
            },
            replaceChildren(...children) {
                this.children = children;
            },
            append(...children) {
                this.children.push(...children);
            },
            appendChild(child) {
                this.children.push(child);
            },
        };
    }

    const element = id => {
        if (!nodes.has(id)) nodes.set(id, makeElement());
        return nodes.get(id);
    };

    element('wordCountSelect').value = '3';
    element('wordlistSelect').value = 'large';
    element('separatorSelect').value = '-';
    element('batchCountSelect').value = '1';

    const context = vm.createContext({
        document: {
            getElementById: element,
            createElement: makeElement,
        },
        console: { error() {} },
        wordlistSizes: {
            large: words.length,
            short: words.length,
        },
        calculateGenerationEntropy: () => 42,
        copyText() {},
        Uint32Array,
        crypto: {
            getRandomValues(array) {
                array[0] =
                    randomValues[randomIndex++ % randomValues.length];
                return array;
            },
        },
        fetch(url, options) {
            requests.push({ url, options });
            return Promise.resolve({
                ok: true,
                status: 200,
                text: async () => `${words.join('\n')}\n`,
            });
        },
    });

    vm.runInContext(html.slice(start, end), context);
    return { context, element, requests };
}

test('Generation keeps passphrases out of requests', async () => {
    const { element, requests } = setup();

    await element('generateBtn').events.click();

    assert.equal(requests.length, 1);
    assert.equal(requests[0].url, '/wordlists/large.txt');
    assert.equal(requests[0].options.method, 'GET');
    assert.equal('body' in requests[0].options, false);
    assert.equal(
        element('passphraseOutput').value,
        'alpha-bravo-charlie'
    );
    assert.equal(
        JSON.stringify(requests).includes('alpha-bravo-charlie'),
        false
    );
});

test('Loaded wordlist is reused without another request', async () => {
    const { element, requests } = setup();

    await element('generateBtn').events.click();
    await element('generateBtn').events.click();

    assert.equal(requests.length, 1);
});

test('Random-number separators use browser CSPRNG', () => {
    const { context } = setup([0, 1, 2, 3, 4]);

    const phrase = context.generateLocalPassphrase(
        ['alpha', 'bravo', 'charlie'],
        3,
        'number'
    );

    assert.equal(phrase, 'alpha3bravo4charlie');
});

test('Random selection rejects modulo-biased values', () => {
    const { context } = setup([0xFFFFFFFF, 1]);

    assert.equal(context.secureRandomIndex(3), 1);
});

test('Batch output avoids HTML-string insertion', async () => {
    const { element } = setup();
    element('batchCountSelect').value = '2';

    await element('generateBtn').events.click();

    const batch = element('batchContainer');
    assert.equal(batch.children.length, 2);
    assert.equal(batch.children[0].children[0].readOnly, true);
    assert.equal(Object.hasOwn(batch.children[0], 'innerHTML'), false);
});
