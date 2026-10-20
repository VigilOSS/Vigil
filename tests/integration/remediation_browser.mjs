// Native Chrome DevTools client: no browser automation package or external traffic.
import assert from "node:assert/strict";

const [endpoint, url, mode, evidenceCount] = process.argv.slice(2);
const socket = new WebSocket(endpoint);
await new Promise((resolve, reject) => {
  socket.addEventListener("open", resolve, { once: true });
  socket.addEventListener("error", reject, { once: true });
});
let sequence = 0;
const pending = new Map();
socket.addEventListener("message", ({ data }) => {
  const response = JSON.parse(data);
  const task = pending.get(response.id);
  if (!task) return;
  pending.delete(response.id);
  if (response.error) task.reject(new Error(JSON.stringify(response.error)));
  else task.resolve(response.result);
});
function call(method, params = {}) {
  const id = ++sequence;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    socket.send(JSON.stringify({ id, method, params }));
  });
}
async function evaluate(expression) {
  const value = await call("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
  assert(!value.exceptionDetails, JSON.stringify(value.exceptionDetails));
  return value.result.value;
}
async function until(expression) {
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    if (await evaluate(`Boolean(document.body) && (${expression})`)) return;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`Browser condition timed out: ${expression}\n${await evaluate("document.body.innerText")}`);
}
async function click(label) {
  const condition = `[...document.querySelectorAll('button')].find(b => !b.disabled && b.textContent.trim() === ${JSON.stringify(label)})`;
  await until(`Boolean(${condition})`);
  await evaluate(`(${condition}).click()`);
}
try {
  await call("Page.enable");
  await call("Page.navigate", { url });
  await until("document.body.innerText.includes('Acme account boundary')");
  if (mode === "approve-finalized") {
    await until("document.body.innerText.includes('ACME-1')");
  }
  if (mode === "drift") {
    await until("document.body.innerText.includes('Backend restart required')");
  } else if (mode === "fresh") {
    await until("document.querySelectorAll('button').length > 5");
    assert(!(await evaluate("document.body.innerText.includes('Backend restart required')")));
  } else {
    await click("Review");
    await until("document.querySelectorAll('.remediation-requirement-result button').length >= 3");
    if (mode === "carried") {
      await evaluate("document.querySelector('.remediation-requirement-result button').click()");
      await until("document.body.innerText.includes('same tree')");
    } else {
      // Follow a requirement to a receipt beyond the initial twenty-row page.
      await evaluate("[...document.querySelectorAll('.remediation-verification-requirements button')][0].click()");
      await click("Preview red-test.json");
      await until("document.body.innerText.includes('cross-account write')");
      const evidenceButton = await evaluate("[...document.querySelectorAll('button')].find(b => /^Evidence/.test(b.textContent.trim())).textContent.trim()");
      await click(evidenceButton);
      await click("Load more evidence");
      assert(Number.isSafeInteger(Number(evidenceCount)) && Number(evidenceCount) > 20);
      await until(`document.querySelectorAll('figure[id^=remediation-evidence-]').length === ${Number(evidenceCount)}`);
      await click("Preview note-0.txt");
      await until("document.body.innerText.includes('<script>window.acmeInjected = true</script>')");
      assert.equal(await evaluate("Boolean(window.acmeInjected)"), false);
      await click("Review");
      await until("document.querySelector('.remediation-diff pre') !== null");
      await evaluate(`(() => {
        const input = document.getElementById('remediation-reviewer');
        Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, 'Acme owner');
        input.dispatchEvent(new Event('input', { bubbles: true }));
      })()`);
      await click("Approve reviewed snapshot");
      await until("[...document.querySelectorAll('.remediation-section-heading')].some(h => h.querySelector('h3')?.textContent === 'Review approval' && h.querySelector('span')?.textContent === 'Current')");
      assert(await evaluate("document.body.innerText.includes('Latest approval: Acme owner')"));
    }
  }
  console.log(`Acme remediation browser E2E passed: ${mode}`);
} finally {
  socket.close();
}
