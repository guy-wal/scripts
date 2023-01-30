use connector-firewall

function getRandomInt(max) {
  return Math.floor(Math.random() * max);
}
for (var x = 0; x < 10000; x++) {
  const documents = [];
  for (var i = 0; i < 10000; i++) {
    var protection_name = getRandomInt(1000).toString();
    var loguid = getRandomInt(1000000000000000).toString();
    var date = new Date();
    var act = ['NA', 'Block', 'Allow', 'inactive'][getRandomInt(3)];
    var direction = ['int-int', 'int-ext', 'ext-ext', 'ext-int'][
      getRandomInt(3)
    ];
    var doc = {
      original_cef: {
        cnt: 1,
        vendor: 'CP',
        dpt: 0,
        proto: '',
        request: '',
        request_method: '',
        rule_name: '',
        rule_uid: '',
        session_id: '',
        spt: 0,
        user_agent: '',
        loguid: '1667818059560',
        act: 'NA',
        rt: date,
        origin_asset_uid: '',
        origin_asset_ip_address: '10.1.100.22',
        src: '10.1.0.55',
        dst: '10.1.0.32',
        severity: 'Medium',
        cs2Label: 'Protection ID',
        cs2: 'some',
        cs4Label: 'Protection Name',
        cs4: '695',
        product: 'IPS',
        sort_string: 'ips',
      },
      rule_uid: '',
      origin_asset_ip_address: '10.1.100.22',
      origin_asset_uid: '',
      direction: direction,
      cnt: 1,
      act: act,
      protection_name: protection_name,
      protection_id: 'some',
      created: date,
      dst: '10.1.0.32',
      src: '10.1.0.55',
      loguid: loguid,
    };
    documents.push(doc);
  }
  db.security_logs.insertMany(documents);
}

