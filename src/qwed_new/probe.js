// QWED probe: JS engine coverage — intentionally vulnerable.
function renderComment(html) {
    document.getElementById("c").innerHTML = html; // XSS sink
}

function runUser(code) {
    return eval(code); // dynamic execution
}

function merge(target, source) {
    for (const k in source) {
        target[k] = source[k]; // prototype pollution if k === '__proto__'
    }
    target["__proto__"]["polluted"] = true;
}

const { exec } = require("child_process");
exec("ls " + process.argv[2]); // command injection

const timed = setTimeout("console.log('string-eval')", 100);
const ctor = new Function("return process")();
