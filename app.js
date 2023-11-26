//express
var express = require('express');
var bodyPaser = require('body-parser');
var session = require('express-session');
var MySQLStore = require('express-mysql-session')(session);

//passport
var mysql = require('mysql2');
var conn = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'crud'
});
conn.connect();
var bkfd2Password = require('pbkdf2-password');
var hasher = bkfd2Password();
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;


//express
var app = express();
app.use(bodyPaser.urlencoded({ extended: false }));
app.use(session({
    secret: 'sdfsdf#$',
    resave: false,
    saveUninitialized: true,
    store: new MySQLStore({
        host: 'localhost',
        port: 3306,
        user: 'root',
        password: '',
        database: 'crud'
    })
}));

//passport
app.use(passport.initialize());
app.use(passport.session());
passport.serializeUser(function (user, done) {
    done(null, user.authId);
});
passport.deserializeUser(function(id, done){
    var sql = 'SELECT * FROM users';
    conn.query(sql, function (err, results) {
        for(var i=0; i<results.length; i++){
            var user = results[i];
            if(user.authId === id){
                return done(null, user);
            }
        }
        done('there is no user.');
    });
});
passport.use(new LocalStrategy(
    function (username, password, done) {
        var uname = username;
        var pwd = password;
        var sql = 'SELECT * FROM users WHERE user_name = ?';
        conn.query(sql, [uname], function (err, results) {
            for (var i = 0; i < results.length; i++) {
                var user = results[i];
                if (uname === user.user_name) {
                    return hasher({ password: pwd, salt: user.salt }, function (err, pass, salt, hash) {
                        if (hash === user.password) {
                            done(null, user);
                        } else {
                            done(null, false);
                        }
                    });
                }
            }
            done(null, false);
        });
    }
));


app.get('/main', function (req, res) {
    var output;
    if (req.user && req.user.user_name) {
        var sql = 'SELECT title FROM posts WHERE user_id = ?';
        conn.query(sql, req.user.user_id, function(err, results){
            var list = '<ul>';
            results.forEach(function(post) {
                list += `<li><a href="/main/list/read/${post.title}">${post.title}</a></li>`;
            });
            list += '</ul>';
            output = `
            <h1>main, ${req.user.user_name}</h1>
            <a href="/auth/login">Logout</a>
            ${list}
            <a href="/main/list/create">New</a>
            `;
            res.send(output);    
        })
    }
    else {
        output = `
        <h1>main</h1>
        <ul>
            <li><a href="/auth/login">Login</a></li>
            <li><a href="/auth/register">Register</a></li>
        </ul>
        `;
        res.send(output);
    }
});

app.get('/auth/login', function (req, res) {
    var output = `
        <h1>/auth/login</h1>
        <form action="/auth/login" method="post">
            <p>
                <input type="text" name="username" placeholder="username" />
            </p>
            <p>
                <input type="password" name="password" placeholder="password" />
            </p>
            <p>
                <input type="submit" />
            </p>
            <li><a href="/auth/register">Register</a></li>
        </form>
    `;
    res.send(output);
});
app.post('/auth/login',
    passport.authenticate(
        'local',
        {
            successRedirect: '/main',
            failureRedirect: '/auth/list/read',
            failureFlash: false
        }
    )
);

app.get('/auth/register', function (req, res) {
    var output = `
        <h1>/auth/register</h1>
        <form action='/auth/register', method='post'>
        <p>
            <input type="text" name="username" placeholder="username" />
        </p>
        <p>
            <input type="password" name="password" placeholder="password" />
        </p>
        <p>
            <input type="text" name="email" placeholder="email" />
        </p>
        <p>
            <input type="submit" />
        </p>
        </form>
    `;
    res.send(output);
});
app.post('/auth/register', function (req, res) {
    var output = `
        <h1>/auth/register</h1>
        <form action='/auth/register', method='post'>
        <p>
            <input type="text" name="username" placeholder="username" />
        </p>
        <p>
            <input type="password" name="password" placeholder="password" />
        </p>
        <p>
            <input type="text" name="email" placeholder="email" />
        </p>
        <p>
            <input type="submit" />
        </p>
        </form>
    `;
    hasher({ password: req.body.password }, function (err, pass, salt, hash) {
        var user = {
            authId: 'local:' + req.body.username,
            user_name: req.body.username,
            email: req.body.email,
            password: hash,
            salt: salt,
        };
        var sql = 'INSERT INTO users SET ?';
        conn.query(sql, user, function (err, results) {
            if (err) {
                console.log(err);
                res.status(500);
            }
            else {
                res.redirect('/main');
            }
        });
    });
});

app.get('/auth/logout', function (req, res) {
    req.logout(function (err) {
        if (err) {
            console.error(err);
        }
    });
    req.session.save(function () {
        res.redirect('/main');
    });
});

app.get('/main/list/read/:title', function (req, res) {
    var title = req.params.title;
    var sql = 'SELECT * FROM posts WHERE user_id = ? and title = ?';
    var params = [req.user.user_id, title];
    var content;
    conn.query(sql, params, function(err, results){
        content = results[0].content;
        var output = `
        <h1>/main/list/read</h1>
        <h2>${req.user.user_name}</h2>
        <h3>${title}</h3>
        <div>${content}</div>
        <a href='/main/list/update/${title}'>edit</a>
        <a href='/main/list/delete/${title}'>delete</a>
        `;
    res.send(output);
    });
});

app.get('/main/list/create', function (req, res) {
    var output;
    if (req.user && req.user.user_name) {
        output = `
            <h1>/main/list/create</h1>
            <h2>${req.user.user_name}</h2>
            <form action='/main/list/create', method='post'>
            <p>
                <input type="text" name="title" placeholder="title" />
            </p>
            <p>
                <input type="text" name="content" placeholder="content" />
            </p>
            <p>
                <input type="submit" />
            </p>
            </form>
        `;
        res.send(output);
    }
    else {
        res.redirect('/main');
    }
});
app.post('/main/list/create', function(req, res){
    var user_id = req.user.user_id;
    var title = req.body.title;
    var content = req.body.content;
    var sql = 'INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)';
    var params = [user_id, title, content];
    conn.query(sql, params, function(err, results){
        if(err){
            console.log(err);
            res.status(500);
        }
        else{
            res.redirect('/main');
        }
    });
});

app.get('/main/list/update/:title', function (req, res) {
    var title = req.params.title;
    var sql = 'SELECT * FROM posts WHERE user_id = ? and title = ?';
    var params = [req.user.user_id, title];
    var content;
    conn.query(sql, params, function(err, results){
        content = results[0].content;
        var output = `
        <h1>/main/list/update</h1>
        <h2>${req.user.user_name}</h2>
        <h3>${title}</h3>
        <form action='/main/list/update/${title}', method='post'>
            <p>
                <input type="text" name="content" placeholder='${content}' />
            </p>
            <p>
                <input type="submit" />
            </p>
        </form>
        `;
        res.send(output);
        });
});
app.post('/main/list/update/:title', function(req, res){
    var title = req.params.title;
    var sql = 'UPDATE posts SET content = ? WHERE user_id = ? and title = ?';
    var edit_content = req.body.content;
    var params = [edit_content, req.user.user_id, title];
    conn.query(sql, params, function(err, results){
        res.redirect('/main');
    });
});
app.get('/main/list/delete/:title', function (req, res) {
    var title = req.params.title;
    var sql = 'DELETE FROM posts WHERE user_id = ? and title = ?';
    var params = [req.user.user_id, title];
    conn.query(sql, params, function(err, results){
        res.redirect('/main');
    });
});

app.listen(1337, function () {
    console.log('connected 3000 port');
});
