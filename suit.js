const { exec, execSync } = require('child_process');

// libcsuit accepts only DER keys.

var genDistributeManifest = (manifest_fname,tcbinary_fname) => {
    let tc_signer_keypath = "./testfiles/key/trust_anchor_secp256r1.der";
    let TCManifest_path = "../../TAs/" + manifest_fname;
    let commands_manifestT = `./suit_for_teep_dependee ${tc_signer_keypath} ${TCManifest_path}`;
    let ret = execSync(commands_manifestT, {
        cwd: '/usr/src/app/suit/libcsuit'
    }
    );
    console.log(ret.toString());

    let tc_uri = "http://localhost:8888/TAs/" + tcbinary_fname;
    let tam_keypath = "../../key/tam_prime256v1.der";
    let manifest_orgname = manifest_fname.replace('.cbor','');
    let TAMManifest_path = "../../TAs/" + manifest_fname + "_TAM.cbor";
    let commands_manifestD = `./suit_for_teep_depending ${TCManifest_path} ${tc_uri} ${tam_keypath}  ${TAMManifest_path}`;
    ret = execSync(commands_manifestD, {
        cwd: '/usr/src/app/suit/libcsuit'
    }
    );
    console.log(ret.toString());

    console.log("finished generateManifest");
}

// var genDistributeManifest = (manifest_fname,tcbinary_fname) => {
//     let tc_signer_keypath = "./testfiles/key/trust_anchor_secp256r1.der";
//     let TCManifest_path = "./tmp/suit_manifest_expT.cbor";
//     let commands_manifestT = `./suit_for_teep_dependee ${tc_signer_keypath} ${TCManifest_path}`;
//     let ret = execSync(commands_manifestT, {
//         cwd: '/usr/src/app/suit/libcsuit'
//     }
//     );
//     console.log(ret.toString());

//     let tc_uri = "http://localhost:8888/TAs/8d82573a-926d-4754-9353-32dc29997f74.ta";
//     let tam_keypath = "../../key/tam_prime256v1.der";
//     let TAMManifest_path = "./tmp/suit_manifest_expD.cbor";
//     let commands_manifestD = `./suit_for_teep_depending ${TCManifest_path} ${tc_uri} ${tam_keypath}  ${TAMManifest_path}`;
//     ret = execSync(commands_manifestD, {
//         cwd: '/usr/src/app/suit/libcsuit'
//     }
//     );
//     console.log(ret.toString());

//     console.log("finished generateManifest");
// }

// exec('make -f Makefile.teep test', {
//     cwd: '/usr/src/app/suit/libcsuit'
// }, (err, stdout, stderr) => {
//     if (err) {
//         console.log(`stderr: ${stderr}`);
//         return;
//     }
//     console.log(`stdout: ${stdout}`);
// });
//genDistributeManifest();
var suit = new Object();
suit.genDistributeManifest = genDistributeManifest;
module.exports = suit;