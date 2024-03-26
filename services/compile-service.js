const fs = require("fs");
const { exec } = require("child_process");
const path = require('path');
const { v4: uuid } = require('uuid');

const dirCodes = path .join(__dirname, "../storage/codes");
if(!fs.existsSync(dirCodes)){
    fs.mkdirSync(dirCodes, {recursive: true});
}

const outputPath = path.join(__dirname, "../storage/outputs");
if (!fs.existsSync(outputPath)){
        fs.mkdirSync(outputPath, { recursive: true});
    }
    
const generateFile = async (format, content) => {
    console.log(outputPath);
    extension = null;
    switch (format) {
        case 'C++':
            extension = 'cpp';
            break;

        case 'Python':
            extention = 'py';
            break;
    }

    const jobid = uuid();
    const filename = `${jobid}.${extension}`;
    const filepath = path.join(dirCodes, filename);
    await fs.writeFileSync(filepath, content);
    return filepath;
};

const executeCpp = (filepath) => {
    const jobId = path.basename(filepath).split(".")[0];
    const outPath = path.join(outputPath, `${jobId}.out`);

    return new Promise((resolve, reject) => {
        exec(`g++ "${filepath}" -o "${outPath}" && cd "${outputPath}" && "./${jobId}.out"`, 
        (error, stdout, stderr) => {
            // error && reject({error,stderr});
            // stderr && reject(stderr);
            // resolve(stdout);
            if(error){
                console.error(`Error: ${error.message}`);
                reject({error,stderr});
                
            }
            else if(stderr){
                console.error(`Stderr: ${stderr}`);
                reject(stderr);
            }
            else {
            resolve(stdout);
            }
        }
        );
    });
};


const executePy = (filepath) => {
    
    return new Promise((resolve, reject) => {
        exec(`python3 "${filepath}"`, 
        (error, stdout, stderr) => {
            // error && reject({error,stderr});
            // stderr && reject(stderr);
            // resolve(stdout);
            if(error){
                console.error(`Error: ${error.message}`);
                reject({error,stderr});
                
            }
            else if(stderr){
                console.error(`Stderr: ${stderr}`);
                reject(stderr);
            }
            else {
            resolve(stdout);
            }
        }
        );
    });
};

module.exports = {
    executePy,
    executeCpp,
    generateFile
}