const { Host } = require("@extism/js-pdk");

function run_scan() {
    let input = Host.inputString();
    let ctx = JSON.parse(input);
    
    let findings = [
        {
            title: "Sample Finding",
            severity: "INFO",
            description: "Scanned target: " + ctx.target
        }
    ];
    
    Host.outputString(JSON.stringify(findings));
}

module.exports = { run_scan };
