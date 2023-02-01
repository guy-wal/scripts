const fs = require("fs");
const { EOL } = require("os");
const amqp = require("amqplib");

function getRandomInt(max) {
  return Math.floor(Math.random() * max);
}

function getRandomIntWithMinimum1(max) {
  return Math.max(1, Math.floor(Math.random() * max));
}

function getRandomIP() {
  return `${getRandomInt(256)}.${getRandomInt(256)}.${getRandomInt(
    256
  )}.${getRandomInt(256)}`;
}

function getArrayFromCsvValue(value) {
  return value
    .replaceAll('"', "")
    .replace("{", "")
    .replace("}", "")
    .split(",")
    .map((cve) => cve.trim());
}

function getRandomProtections(n) {
  const file = fs.readFileSync("mds_protections.csv").toString();

  rows = file.split(EOL);
  const protections = [];
  const headers = rows[0]
    .split(",")
    .map((header) => header.replaceAll('"', "").trim());
  console.log("headers", headers);

  const stringArrayColumnNames = ["cves", "service", "os"];
  for (let i = 1; i < rows.length; i++) {
    const data = rows[i].split(",");
    const obj = {};

    for (let j = 0; j < data.length; j++) {
      const key = headers[j];
      const value = data[j].replaceAll('"', "").trim();
      if (stringArrayColumnNames.includes(key)) {
        obj[key] = getArrayFromCsvValue(value);
        continue;
      }
      obj[key] = value;
    }
    protections.push(obj);
  }
  const randomProtections = [];
  let seenProtections = [];
  for (let i = 0; i < n; i++) {
    let protectionIndex;
    do {
      protectionIndex = getRandomInt(protections.length);
    } while (seenProtections.includes(protectionIndex));
    seenProtections.push(protectionIndex);
    randomProtections.push(protections[protectionIndex]);
  }
  return randomProtections;
}

function getRulesAndProfiles() {
  const file = fs.readFileSync("rules_to_profiles.csv").toString();

  rows = file.split(EOL);
  const rulesAndProfiles = [];
  const headers = rows[0]
    .split(",")
    .map((header) => header.replaceAll('"', "").trim());
  console.log("headers", headers);

  for (let i = 1; i < rows.length; i++) {
    const data = rows[i].split(",");
    const obj = {};

    for (let j = 0; j < data.length; j++) {
      const key = headers[j];
      const value = data[j].replaceAll('"', "").trim();
      obj[key] = value;
    }
    rulesAndProfiles.push(obj);
  }
  return rulesAndProfiles;
}

(async function main() {
  const numOfLogs = process.argv[2];
  const numOfTimes = process.argv[3] ?? 1;
  console.log("numOfLogs", numOfLogs);

  const protections = getRandomProtections(2000);

  const rulesToProfiles = getRulesAndProfiles();

  const connection = await amqp.connect("amqp://test:test@localhost");

  const channel = await connection.createChannel();
  var queue = "ConnectorFirewall-SecurityLogsQueue";
  await channel.assertQueue(queue);

  for (let i = 0; i < numOfLogs; i++) {
    const protection = protections[getRandomInt(protections.length)];
    const ruleToProfile = rulesToProfiles[getRandomInt(rulesToProfiles.length)];
    const loguid = getRandomInt(1000000000000000).toString();
    const date = new Date();
    const act = ["NA", "Block", "Allow", "Inactive"][getRandomInt(3)];
    const severity = ["NA", "Low", "Medium", "High", "Critical"][
      getRandomInt(5)
    ];
    const direction = ["int-int", "int-ext", "ext-int"][getRandomInt(3)];

    const origin_asset_ip_address = ["10.1.250.11", "10.1.250.9"][
      getRandomInt(1)
    ];

    const src = direction.includes("int-")
      ? `10.1.250.${getRandomIntWithMinimum1(15)}`
      : getRandomIP();
    const dst = direction.includes("-int")
      ? `10.1.250.${getRandomIntWithMinimum1(15)}`
      : getRandomIP();

    const original_cef = {
      cnt: getRandomIntWithMinimum1(10),
      vendor: "CP",
      dpt: 0,
      proto: "",
      request: "",
      request_method: "",
      rule_name: ruleToProfile.rule_name,
      rule_uid: ruleToProfile.rule_uid,
      session_id: getRandomInt(1000000000000000).toString(),
      spt: 0,
      user_agent: "",
      loguid: loguid,
      act,
      rt: date,
      origin_asset_ip_address,
      src,
      dst,
      severity,
      cs2Label: "Protection ID",
      cs2: protection.id,
      cs4Label: "Protection Name",
      cs4: protection.name,
      product: "IPS",
      sort_string: "ips",
    };
    channel.sendToQueue(queue, Buffer.from(JSON.stringify(original_cef)));
  }

  console.log("done");
})();
