"use strict";

module.exports = {
    appDomain: 'http://localhost',
    appPort: 9999,
    exposedDomainUrl: 'http://localhost:9999',
    apiVersions : {
      v1: {
        prefix: '',
        versionNumber: 'v1'
      },
      v2: {
        prefix: 'api',
        versionNumber: 'v2'
      }
    },
    defaultValues : {
      locale : 'te',
      languageId : 'cjt8l3fiw00014vs6szibwjrq',
      country : 'IN'
    },
    mysql: {
      master : {
        url: '127.0.01',
        port: '3306',
        databaseName: 'dialogue_local',
        options: {
          user: 'root',
          pass: 'root@123'
        },
        debug: true
      },
      slave : {
        url: '127.0.01',
        port: '3306',
        databaseName: 'dialogue_local',
        options: {
          user: 'root',
          pass: 'root@123'
        },
        debug: true
      }
    },
    redis: {
      projectPrefix: 'dialogue:',
      sessionSecret: 'R3$#4SERIO93@W323',
      sessionPrefix: 'dialogue_sess_rt_',
      auth: {
        port: '6379',
        host: 'localhost',
        pass: 'Redis@123'
      }
    },
    neo4j: {
      master : {
        host: '127.0.0.1',
        port: '3306',
        databaseName: 'neo4j',
        options: {
          user: 'neo4j',
          pass: 'Neo4j@123'
        },
        debug: true
      },
      slave : {
        url: '127.0.0.1',   
        port: '3306',
        databaseName: 'neo4j',
        options: {
          user: 'neo4j',
          pass: 'Neo4j@123'
        },
        debug: true
      }
    },
    bcrypt: {
      saltRounds: 10
    },
    facebook : {
      clientID: '1273922623026417',
      clientSecret: '557bba7bf085725708a056576b7761a0',
      callbackURL: "/oauth/facebook/callback"
    },
    google : {
      // clientID: '1004430022205-02oenplbrusbdotncdkbn821q5lq0oak.apps.googleusercontent.com',
      // clientSecret: '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',
      // callbackURL: '/oauth/google/callback',
      // clientID: '746362804937-7fqrnoeed2sv98sghet5klrlt470928h.apps.googleusercontent.com',
      // clientSecret: 'lLKYWzOWXzWZg6_IsBhdrYaF',
      // callbackURL: 'https://brochill.com/users/oauth/google'
      // clientID: '746362804937-7fqrnoeed2sv98sghet5klrlt470928h.apps.googleusercontent.com',
      // clientSecret: 'lLKYWzOWXzWZg6_IsBhdrYaF',
      // callbackURL: 'https://brochill.com/users/oauth/google' 
      clientID: '418048044687-u7lm08mkrd8u84osfipeq4aqru8ceiq2.apps.googleusercontent.com',
      clientSecret: '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',
      callbackURL: '/oauth/google/callback'
    },
    jwt : {
      secret : 'Tn7Kby*CX?2y=BDazw',
      expiresIn : 900,
      expiresInMilliseconds : 9000000000
    },
    refreshToken : {
      secret : '#:9(95Hv&2>8Q7[pF~!Xv_],q3=',
      expiresIn : 2592000,
      expiresInMilliseconds : 2592000000
    },
    moment : {
      dbFormat : 'YYYY-MM-DD HH:mm:ss'
    },
    aes256gcm : {
      secret : '5yQt\~W2gG6r(uYUGDy?qe7t$-Cn^**59'
    },
    sendgrid : {
      apiKey : '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',
      fromEmail : 'no-reply@brochill.app',
      fromName : 'Brochill Support',
      templates : {
        resetPassword : 'd-2e79b4061e6a4a7c8b1592f3b677ee7d',
        regSuccess : 'd-f9aa7bec680649eeab9ec252a046ea26'
      }
    },
    bcrypt : {
      saltRounds : 10,
      resetPwdTokenSaltRounds : 9
    },
    cookieDomain : '.pushpa.club',
    pagination : {
      itemsPerPage : 5,
      limit: 10,
      page: 1
    },
    encrytpion : {
      key : "5CNC5D1H4yxzP8OT/KHf0MAo89hEHQKdl6CPs02UlYRLS7/t2WtDk76dULONdpCE"
    },
    kafka: {
      clientId: '1234',
      brokers: ['localhost:9093'],
      maxRetries: 3,
      retryDelay: 5000,
      groupId: '',
      topicName: "",
      dlqTopicName: ''
    },
    clientUrl: 'http://localhost:5173'
  }
  