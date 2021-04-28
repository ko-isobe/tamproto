const { exec } = require('child_process');

exec('make -f Makefile.encode test',{
    cwd: '/usr/src/app/suit/libcsuit'
},(err,stdout,stderr)=>{
    if (err){
        console.log(`stderr: ${stderr}`);
        return;
    }
    console.log(`stdout: ${stdout}`);
});
console.log("hoge");