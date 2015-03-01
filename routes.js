// routes.js
// here we do routing of all the pages and their GET and POST requests.
var _ = require('lodash');
var crypto = require('crypto');
var fs = require('fs');
var jsencrypt = require('./jsencrypt.js').create(__dirname + '/rsa_1024_priv.pem', __dirname + '/rsa_1024_pub.pem');
var users = JSON.parse(fs.readFileSync('./users.json', 'utf8'));
var qs = require('querystring');

module.exports = function(app, passport) {
    var algorithms = [];    //array of algorithms that we will run checks on
    var serverTime = 0.0;   //server processing time;
    var clientTime = "";        //the client's preocessing time we recieved 
    var ALGORITHM1 = 'sha1';    //our primary algorithm
    var ALGORITHM2 = 'md5';     //our secondary algorithm used in 2key approach
    var KEY1 = 'key1';          //our first key
    var KEY2 = 'key2';          //our second key
    var publicKey = jsencrypt.getPublicKey();       //public key for encryption
    var privateKey = jsencrypt.getPrivateKey();     //private key for decryption
    var plainHash = false, 
        keyHash = false, 
        pkiHash = false, 
        passwordHash = false, 
        sessionHash = false, 
        twoHash = false;    //set all the integrity checks default to false

    // =====================================
    // HOME PAGE (with login links) ========
    // =====================================
    app.get('/', function(req, res) {
        res.render('index.jade'); // load the index.jade file
    });

    // =====================================
    // LOGIN ===============================
    // =====================================
    // show the login form
    app.get('/login', function(req, res) {
        // render the page and pass in any flash data if it exists
        res.render('login.jade', { message: req.flash('loginMessage') });
    });

    // process the login form
    app.post('/login', passport.authenticate('local', {
        successRedirect : '/profile', // redirect to the secure profile section
        failureRedirect : '/login', // redirect back to the signup page if there is an error
        failureFlash : true // allow flash messages
    }));

    // =====================================
    // Algorithm selection Section =====================
    // =====================================
    // we will want this protected so you have to be logged in to visit
    // we will use route middleware to verify this (the isLoggedIn function)
    app.get('/profile', isLoggedIn, function(req, res) {
        res.render('profile.jade', {
            user : req.user, // get the user out of session and pass to template
        });
    });

    app.post('/profile', isLoggedIn, function(req, res) {
        algorithms = req.body.algorithm;    //the algorithms that the user selected to run integrity checks on
        //console.log(algorithms);
        res.redirect('/item');
    });

    // =====================================
    // ITEM SECTION =====================
    // =====================================
    // we will want this protected so you have to be logged in to visit
    // we will use route middleware to verify this (the isLoggedIn function)
    app.get('/item', isLoggedIn, function(req, res) {
        // key1 is needed in algorithms 2 and 6
        if (_.indexOf(algorithms, '2') !== -1 || _.indexOf(algorithms, '6') !== -1) {
            res.setHeader('key1', KEY1);
            
            //key2 is also needed in algorithm 6
            if (_.indexOf(algorithms, '6') !== -1) {
                res.setHeader('key2', KEY2);
            }
        }
        //public key is need in algorithm 3 from encryption
        if (_.indexOf(algorithms, '3') !== -1) {
            res.setHeader('pubkey', publicKey);
        }
        
        res.render('item.jade', {
            algorithms: algorithms
        });
    });

    app.post('/item', isLoggedIn, function(req, res) {
        var body = "";      //storing data recieved from client here
        //set all check values to false 
        plainHash = false; 
        keyHash = false; 
        pkiHash = false; 
        passwordHash = false; 
        sessionHash = false; 
        twoHash = false; 
        var startTime, endTime;     //store start and end times for performance checking

        //once we recieved data start performing integrity checks
        req.on('data', function(data){
            body += data;   //store data we recieved in body
            startTime = Date.now();     //get the start time

            //user selected plain hash
            if (_.indexOf(algorithms, '1') !== -1) {
                plainHash = checkPlainHash(ALGORITHM1, body, req.headers.plainhash);
            }
            //user selected hash with security key
            if (_.indexOf(algorithms, '2') !== -1) {
                keyHash = checkKeyHash(ALGORITHM1, KEY1, body, req.headers.keyhash);
            }
            //user selected hash with pki enrpyption
            if (_.indexOf(algorithms, '3') !== -1) {
                var symkey = jsencrypt.decrypt(req.headers.symkey);
                pkiHash = checkPkiHash(ALGORITHM1, symkey, body, req.headers.pkihash);
            }
            //user selected hash with password
            if (_.indexOf(algorithms, '4') !== -1) {
                var post = qs.parse(body);
                // check if user entered password is correct
                if(req.user.password == post.password) {
                    passwordHash = checkPasswordHash(ALGORITHM1, post.password, body, req.headers.passwordhash);
                } else {
                    res.end('0');  //else send password incorrect
                }
            }
            //user selected hash with session
            if (_.indexOf(algorithms, '5') !== -1) {
                sessionHash = checkSessionHash(ALGORITHM1, req.sessionID, body, req.headers.sessionhash);
            }
            //user selected hash with 2 key 2 hash
            if (_.indexOf(algorithms, '6') !== -1) {
                twoHash = checkTwoHash(ALGORITHM1, ALGORITHM2, KEY1, KEY2, body, req.headers.firsthash, req.headers.secondhash);
            }
            endTime = Date.now();       //get the end time
        });

        processingTime = parseFloat(endTime - startTime);   //calculate time taken
        clientTime = parseFloat(req.headers.clienttime);    //get the client's time

        res.end('1');    //go to results page 
    });

    // =====================================
    // RESULT ==============================
    // =====================================
    app.get('/result', isLoggedIn, function(req, res) {
        res.render('result.jade', {
            // send the results to render them 
            algorithms : algorithms, 
            plainhash: plainHash,
            keyhash: keyHash, 
            pkihash: pkiHash, 
            passwordhash: passwordHash, 
            sessionhash: sessionHash, 
            twohash: twoHash,
            servertime: processingTime.toString(),
            clienttime: clientTime.toString(),
            time: parseFloat(processingTime + clientTime)
        });
    });
    // =====================================
    // LOGOUT ==============================
    // =====================================
    app.get('/logout', function(req, res) {
        req.logout();
        res.redirect('/');
    });
};

// route middleware to make sure a user is logged in
function isLoggedIn(req, res, next) {

    // if user is authenticated in the session, carry on 
    if (req.isAuthenticated())
        return next();

    // if they aren't redirect them to the home page
    res.redirect('/');
}


function checkPlainHash(algorithm, data, headerHash) {
    //console.log("\n**************** Integrity Check method: Plain Hash ****************");
    //console.log('plainhash: ', headerHash);
    var hash = crypto.createHash(algorithm).update(data).digest('hex');
    //console.log('plainhash generated: ', hash);
    return hash == headerHash;
}

function checkKeyHash(algorithm, key, data, headerHash) {
    //console.log("\n**************** Integrity Check method: Hash with security key ****************");
    //console.log('keyhash: ', headerHash);
    var hash = crypto.createHmac(algorithm, key);
    hash.setEncoding('hex');
    hash.write(data);
    hash.end();
    hash = hash.read();
    //console.log('keyhash generated: ', hash);
    return hash == headerHash;
}

function checkPkiHash(algorithm, key, data, headerHash) {
    //console.log("\n**************** Integrity Check method: Hash with security key encrypted with PKI ****************");
    //console.log('pkihash: ', headerHash);
    var hash = crypto.createHmac(algorithm, key);
    hash.setEncoding('hex');
    hash.write(data);
    hash.end();
    hash = hash.read();
    //console.log('pkihash generated: ', hash);
    return hash == headerHash;
}

function checkPasswordHash(algorithm, key, data, headerHash) {
    //console.log("\n**************** Integrity Check method: Hash with password ****************");
    //console.log('passwordhash: ', headerHash);
    var hash = crypto.createHmac(algorithm, key);
    hash.setEncoding('hex');
    hash.write(data);
    hash.end();
    hash = hash.read();
    //console.log('passwordhash generated: ', hash);
    return hash == headerHash;
}

function checkSessionHash(algorithm, key, data, headerHash) {
    //console.log("\n**************** Integrity Check method: Hash with session ****************");
    //console.log('sessionhash: ', headerHash);
    var hash = crypto.createHmac(algorithm, key);
    hash.setEncoding('hex');
    hash.write(data);
    hash.end();
    hash = hash.read();
    //console.log('sessionhash generated: ', hash);
    return hash == headerHash;
}

function checkTwoHash(algorithm1, algorithm2, key1, key2, data, headerHash1, headerHash2) {
    //console.log("\n**************** Integrity Check method: 2 hash, 2 key, 2 algorithms ****************");
    
    //console.log('first hash: ', headerHash1);
    var hash1 = crypto.createHmac(algorithm1, key1);
    hash1.setEncoding('hex');
    hash1.write(data);
    hash1.end();
    hash1 = hash1.read();
    //console.log('first hash generated: ', hash1);

    //console.log('second hash: ', headerHash2);
    var hash2 = crypto.createHmac(algorithm2, key2);
    hash2.setEncoding('hex');
    hash2.write(data);
    hash2.end();
    hash2 = hash2.read();
    //console.log('second hash generated: ', hash2);
    
    return (hash1 == headerHash1 && hash2 == headerHash2);
}