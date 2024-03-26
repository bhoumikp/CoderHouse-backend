const { executePy, executeCpp, generateFile } = require("../services/compile-service");
const Job = require("../models/jobs-model");

class CompilerController {
    async runCode(req, res) {
        const { language = "cpp", code} = req.body;
        console.log(language, code.length);   

        if (code === "") {
            return res.status(400).json({ success: false,  error: "emptycode" });
        }

        try{
            // we'll generate a c++ or py file with content from the request
            const filepath = await generateFile(language, code);
            
            console.log("i m above save job");
            const job = new Job({language, filepath});
            const savedJob = await job.save();
            console.log("below job save");
            // const jobId = job["_id"];
            const jobId = savedJob._id;
            console.log(jobId);
            // res.status(201).json({success: true, jobId});

            // need to run the file and send the respons
            let output;
            if(language === "C++"){
                output = await executeCpp(filepath);
                console.log(`in cpp loop n output is: ${output}`);
            }else{    
                output = await executePy(filepath);  
                console.log(`in py loop n output is: ${output}`);  
            }
            
            return res.json({filepath, output});
            // return res.json(output);
        } catch(error){
            // return res.json({filepath, someError: "error"});
            console.error("Error:", error);
            return res.status(500).json({ message: "Internal Server Error", error: error });
        }
    }
}

module.exports = new CompilerController();