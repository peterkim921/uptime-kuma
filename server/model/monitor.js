const dayjs = require("dayjs");
const axios = require("axios");
const { Prometheus } = require("../prometheus");
const { log, UP, DOWN, PENDING, MAINTENANCE, flipStatus, MAX_INTERVAL_SECOND, MIN_INTERVAL_SECOND,
    SQL_DATETIME_FORMAT, evaluateJsonQuery,
    PING_PACKET_SIZE_MIN, PING_PACKET_SIZE_MAX, PING_PACKET_SIZE_DEFAULT,
    PING_GLOBAL_TIMEOUT_MIN, PING_GLOBAL_TIMEOUT_MAX, PING_GLOBAL_TIMEOUT_DEFAULT,
    PING_COUNT_MIN, PING_COUNT_MAX, PING_COUNT_DEFAULT,
    PING_PER_REQUEST_TIMEOUT_MIN, PING_PER_REQUEST_TIMEOUT_MAX, PING_PER_REQUEST_TIMEOUT_DEFAULT,
    getMonitorRelativeURL
} = require("../../src/util");
const { ping, checkCertificate, checkStatusCode, getTotalClientInRoom, setting, mssqlQuery, postgresQuery, mysqlQuery, setSetting, httpNtlm, radius,
    kafkaProducerAsync, getOidcTokenClientCredentials, rootCertificatesFingerprints, axiosAbortSignal, checkCertificateHostname
} = require("../util-server");
const { R } = require("redbean-node");
const { BeanModel } = require("redbean-node/dist/bean-model");
const { Notification } = require("../notification");
const { Proxy } = require("../proxy");
const { demoMode } = require("../config");
const version = require("../../package.json").version;
const apicache = require("../modules/apicache");
const { UptimeKumaServer } = require("../uptime-kuma-server");
const { DockerHost } = require("../docker");
const Gamedig = require("gamedig");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { UptimeCalculator } = require("../uptime-calculator");
const { CookieJar } = require("tough-cookie");
const { HttpsCookieAgent } = require("http-cookie-agent/http");
const https = require("https");
const http = require("http");

const rootCertificates = rootCertificatesFingerprints();

/**
 * status:
 *      0 = DOWN
 *      1 = UP
 *      2 = PENDING
 *      3 = MAINTENANCE
 */
class Monitor extends BeanModel {

    /**
     * Return an object that ready to parse to JSON for public Only show
     * necessary data to public
     * @param {boolean} showTags Include tags in JSON
     * @param {boolean} certExpiry Include certificate expiry info in
     * JSON
     * @returns {Promise<object>} Object ready to parse
     */
    async toPublicJSON(showTags = false, certExpiry = false) {
        let obj = {
            id: this.id,
            name: this.name,
            sendUrl: this.sendUrl,
            type: this.type,
        };

        if (this.sendUrl) {
            obj.url = this.customUrl ?? this.url;
        }

        if (showTags) {
            obj.tags = await this.getTags();
        }

        if (certExpiry && (this.type === "http" || this.type === "keyword" || this.type === "json-query") && this.getURLProtocol() === "https:") {
            const { certExpiryDaysRemaining, validCert } = await this.getCertExpiry(this.id);
            obj.certExpiryDaysRemaining = certExpiryDaysRemaining;
            obj.validCert = validCert;
        }

        return obj;
    }

    /**
     * Return an object that ready to parse to JSON
     * @param {object} preloadData to prevent n+1 problems, we query the data in a batch outside of this function
     * @param {boolean} includeSensitiveData Include sensitive data in
     * JSON
     * @returns {object} Object ready to parse
     */
    toJSON(preloadData = {}, includeSensitiveData = true) {

        let screenshot = null;

        if (this.type === "real-browser") {
            screenshot = "/screenshots/" + jwt.sign(this.id, UptimeKumaServer.getInstance().jwtSecret) + ".png";
        }

        const path = preloadData.paths.get(this.id) || [];
        const pathName = path.join(" / ");

        let data = {
            id: this.id,
            name: this.name,
            description: this.description,
            path,
            pathName,
            parent: this.parent,
            childrenIDs: preloadData.childrenIDs.get(this.id) || [],
            url: this.url,
            wsIgnoreSecWebsocketAcceptHeader: this.getWsIgnoreSecWebsocketAcceptHeader(),
            wsSubprotocol: this.wsSubprotocol,
            method: this.method,
            hostname: this.hostname,
            port: this.port,
            maxretries: this.maxretries,
            weight: this.weight,
            active: preloadData.activeStatus.get(this.id),
            forceInactive: preloadData.forceInactive.get(this.id),
            type: this.type,
            timeout: this.timeout,
            interval: this.interval,
            retryInterval: this.retryInterval,
            resendInterval: this.resendInterval,
            keyword: this.keyword,
            invertKeyword: this.isInvertKeyword(),
            expiryNotification: this.isEnabledExpiryNotification(),
            ignoreTls: this.getIgnoreTls(),
            upsideDown: this.isUpsideDown(),
            packetSize: this.packetSize,
            maxredirects: this.maxredirects,
            accepted_statuscodes: this.getAcceptedStatuscodes(),
            dns_resolve_type: this.dns_resolve_type,
            dns_resolve_server: this.dns_resolve_server,
            dns_last_result: this.dns_last_result,
            docker_container: this.docker_container,
            docker_host: this.docker_host,
            proxyId: this.proxy_id,
            notificationIDList: preloadData.notifications.get(this.id) || {},
            tags: preloadData.tags.get(this.id) || [],
            maintenance: preloadData.maintenanceStatus.get(this.id),
            mqttTopic: this.mqttTopic,
            mqttSuccessMessage: this.mqttSuccessMessage,
            mqttCheckType: this.mqttCheckType,
            databaseQuery: this.databaseQuery,
            authMethod: this.authMethod,
            grpcUrl: this.grpcUrl,
            grpcProtobuf: this.grpcProtobuf,
            grpcMethod: this.grpcMethod,
            grpcServiceName: this.grpcServiceName,
            grpcEnableTls: this.getGrpcEnableTls(),
            radiusCalledStationId: this.radiusCalledStationId,
            radiusCallingStationId: this.radiusCallingStationId,
            game: this.game,
            gamedigGivenPortOnly: this.getGameDigGivenPortOnly(),
            httpBodyEncoding: this.httpBodyEncoding,
            jsonPath: this.jsonPath,
            expectedValue: this.expectedValue,
            kafkaProducerTopic: this.kafkaProducerTopic,
            kafkaProducerBrokers: JSON.parse(this.kafkaProducerBrokers),
            kafkaProducerSsl: this.getKafkaProducerSsl(),
            kafkaProducerAllowAutoTopicCreation: this.getKafkaProducerAllowAutoTopicCreation(),
            kafkaProducerMessage: this.kafkaProducerMessage,
            screenshot,
            cacheBust: this.getCacheBust(),
            remote_browser: this.remote_browser,
            snmpOid: this.snmpOid,
            jsonPathOperator: this.jsonPathOperator,
            snmpVersion: this.snmpVersion,
            smtpSecurity: this.smtpSecurity,
            rabbitmqNodes: JSON.parse(this.rabbitmqNodes),
            conditions: JSON.parse(this.conditions),
            ipFamily: this.ipFamily,
            notification_rules: this.notification_rules,
            notificationRules: (preloadData.notificationRules && preloadData.notificationRules.get(this.id)) || [],

            // ping advanced options
            ping_numeric: this.isPingNumeric(),
            ping_count: this.ping_count,
            ping_per_request_timeout: this.ping_per_request_timeout,

            // dependencies
            dependencies: (preloadData.dependencies && preloadData.dependencies.get(this.id)) || [],
        };

        if (includeSensitiveData) {
            data = {
                ...data,
                headers: this.headers,
                body: this.body,
                grpcBody: this.grpcBody,
                grpcMetadata: this.grpcMetadata,
                basic_auth_user: this.basic_auth_user,
                basic_auth_pass: this.basic_auth_pass,
                oauth_client_id: this.oauth_client_id,
                oauth_client_secret: this.oauth_client_secret,
                oauth_token_url: this.oauth_token_url,
                oauth_scopes: this.oauth_scopes,
                oauth_audience: this.oauth_audience,
                oauth_auth_method: this.oauth_auth_method,
                pushToken: this.pushToken,
                databaseConnectionString: this.databaseConnectionString,
                radiusUsername: this.radiusUsername,
                radiusPassword: this.radiusPassword,
                radiusSecret: this.radiusSecret,
                mqttUsername: this.mqttUsername,
                mqttPassword: this.mqttPassword,
                mqttWebsocketPath: this.mqttWebsocketPath,
                authWorkstation: this.authWorkstation,
                authDomain: this.authDomain,
                tlsCa: this.tlsCa,
                tlsCert: this.tlsCert,
                tlsKey: this.tlsKey,
                kafkaProducerSaslOptions: JSON.parse(this.kafkaProducerSaslOptions),
                rabbitmqUsername: this.rabbitmqUsername,
                rabbitmqPassword: this.rabbitmqPassword,
            };
        }

        data.includeSensitiveData = includeSensitiveData;
        return data;
    }

    /**
     * Get all tags applied to this monitor
     * @returns {Promise<LooseObject<any>[]>} List of tags on the
     * monitor
     */
    async getTags() {
        return await R.getAll("SELECT mt.*, tag.name, tag.color FROM monitor_tag mt JOIN tag ON mt.tag_id = tag.id WHERE mt.monitor_id = ? ORDER BY tag.name", [ this.id ]);
    }

    /**
     * Gets certificate expiry for this monitor
     * @param {number} monitorID ID of monitor to send
     * @returns {Promise<LooseObject<any>>} Certificate expiry info for
     * monitor
     */
    async getCertExpiry(monitorID) {
        let tlsInfoBean = await R.findOne("monitor_tls_info", "monitor_id = ?", [
            monitorID,
        ]);
        let tlsInfo;
        if (tlsInfoBean) {
            tlsInfo = JSON.parse(tlsInfoBean?.info_json);
            if (tlsInfo?.valid && tlsInfo?.certInfo?.daysRemaining) {
                return {
                    certExpiryDaysRemaining: tlsInfo.certInfo.daysRemaining,
                    validCert: true
                };
            }
        }
        return {
            certExpiryDaysRemaining: "",
            validCert: false
        };
    }

    /**
     * Encode user and password to Base64 encoding
     * for HTTP "basic" auth, as per RFC-7617
     * @param {string|null} user - The username (nullable if not changed by a user)
     * @param {string|null} pass - The password (nullable if not changed by a user)
     * @returns {string} Encoded Base64 string
     */
    encodeBase64(user, pass) {
        return Buffer.from(`${user || ""}:${pass || ""}`).toString("base64");
    }

    /**
     * Is the TLS expiry notification enabled?
     * @returns {boolean} Enabled?
     */
    isEnabledExpiryNotification() {
        return Boolean(this.expiryNotification);
    }

    /**
     * Check if ping should use numeric output only
     * @returns {boolean} True if IP addresses will be output instead of symbolic hostnames
     */
    isPingNumeric() {
        return Boolean(this.ping_numeric);
    }

    /**
     * Parse to boolean
     * @returns {boolean} Should TLS errors be ignored?
     */
    getIgnoreTls() {
        return Boolean(this.ignoreTls);
    }

    /**
     * Parse to boolean
     * @returns {boolean} Should WS headers be ignored?
     */
    getWsIgnoreSecWebsocketAcceptHeader() {
        return Boolean(this.wsIgnoreSecWebsocketAcceptHeader);
    }

    /**
     * Parse to boolean
     * @returns {boolean} Is the monitor in upside down mode?
     */
    isUpsideDown() {
        return Boolean(this.upsideDown);
    }

    /**
     * Parse to boolean
     * @returns {boolean} Invert keyword match?
     */
    isInvertKeyword() {
        return Boolean(this.invertKeyword);
    }

    /**
     * Parse to boolean
     * @returns {boolean} Enable TLS for gRPC?
     */
    getGrpcEnableTls() {
        return Boolean(this.grpcEnableTls);
    }

    /**
     * Parse to boolean
     * @returns {boolean} if cachebusting is enabled
     */
    getCacheBust() {
        return Boolean(this.cacheBust);
    }

    /**
     * Get accepted status codes
     * @returns {object} Accepted status codes
     */
    getAcceptedStatuscodes() {
        return JSON.parse(this.accepted_statuscodes_json);
    }

    /**
     * Get if game dig should only use the port which was provided
     * @returns {boolean} gamedig should only use the provided port
     */
    getGameDigGivenPortOnly() {
        return Boolean(this.gamedigGivenPortOnly);
    }

    /**
     * Parse to boolean
     * @returns {boolean} Kafka Producer Ssl enabled?
     */
    getKafkaProducerSsl() {
        return Boolean(this.kafkaProducerSsl);
    }

    /**
     * Parse to boolean
     * @returns {boolean} Kafka Producer Allow Auto Topic Creation Enabled?
     */
    getKafkaProducerAllowAutoTopicCreation() {
        return Boolean(this.kafkaProducerAllowAutoTopicCreation);
    }

    /**
     * Start monitor
     * @param {Server} io Socket server instance
     * @returns {Promise<void>}
     */
    async start(io) {
        let previousBeat = null;
        let retries = 0;

        try {
            this.prometheus = new Prometheus(this, await this.getTags());
        } catch (e) {
            log.error("prometheus", "Please submit an issue to our GitHub repo. Prometheus update error: ", e.message);
        }

        const beat = async () => {

            let beatInterval = this.interval;

            if (! beatInterval) {
                beatInterval = 1;
            }

            if (demoMode) {
                if (beatInterval < 20) {
                    console.log("beat interval too low, reset to 20s");
                    beatInterval = 20;
                }
            }

            // Expose here for prometheus update
            // undefined if not https
            let tlsInfo = undefined;

            if (!previousBeat || this.type === "push") {
                previousBeat = await R.findOne("heartbeat", " monitor_id = ? ORDER BY time DESC", [
                    this.id,
                ]);
                if (previousBeat) {
                    retries = previousBeat.retries;
                }
            }

            const isFirstBeat = !previousBeat;

            let bean = R.dispense("heartbeat");
            bean.monitor_id = this.id;
            bean.time = R.isoDateTimeMillis(dayjs.utc());
            bean.status = DOWN;
            bean.downCount = previousBeat?.downCount || 0;

            if (this.isUpsideDown()) {
                bean.status = flipStatus(bean.status);
            }

            // Runtime patch timeout if it is 0
            // See https://github.com/louislam/uptime-kuma/pull/3961#issuecomment-1804149144
            if (!this.timeout || this.timeout <= 0) {
                this.timeout = this.interval * 1000 * 0.8; // 0.8 is the default timeout percentage
            }

            try {
                if (await Monitor.isUnderMaintenance(this.id)) {
                    bean.msg = "Monitor under maintenance";
                    bean.status = MAINTENANCE;
                } else if (this.type === "http" || this.type === "keyword" || this.type === "json-query") {
                    // Do not do any queries/high loading things before the "bean.ping"
                    let startTime = dayjs().valueOf();

                    // HTTP basic auth
                    let basicAuthHeader = {};
                    if (this.auth_method === "basic") {
                        basicAuthHeader = {
                            "Authorization": "Basic " + this.encodeBase64(this.basic_auth_user, this.basic_auth_pass),
                        };
                    }

                    // OIDC: Basic client credential flow.
                    // Additional grants might be implemented in the future
                    let oauth2AuthHeader = {};
                    if (this.auth_method === "oauth2-cc") {
                        try {
                            if (this.oauthAccessToken === undefined || new Date(this.oauthAccessToken.expires_at * 1000) <= new Date()) {
                                this.oauthAccessToken = await this.makeOidcTokenClientCredentialsRequest();
                            }
                            oauth2AuthHeader = {
                                "Authorization": this.oauthAccessToken.token_type + " " + this.oauthAccessToken.access_token,
                            };
                        } catch (e) {
                            throw new Error("The oauth config is invalid. " + e.message);
                        }
                    }

                    let agentFamily = undefined;
                    if (this.ipFamily === "ipv4") {
                        agentFamily = 4;
                    }
                    if (this.ipFamily === "ipv6") {
                        agentFamily = 6;
                    }

                    const httpsAgentOptions = {
                        maxCachedSessions: 0, // Use Custom agent to disable session reuse (https://github.com/nodejs/node/issues/3940)
                        rejectUnauthorized: !this.getIgnoreTls(),
                        secureOptions: crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT,
                        autoSelectFamily: true,
                        ...(agentFamily ? { family: agentFamily } : {})
                    };

                    const httpAgentOptions = {
                        maxCachedSessions: 0,
                        autoSelectFamily: true,
                        ...(agentFamily ? { family: agentFamily } : {})
                    };

                    log.debug("monitor", `[${this.name}] Prepare Options for axios`);

                    let contentType = null;
                    let bodyValue = null;

                    if (this.body && (typeof this.body === "string" && this.body.trim().length > 0)) {
                        if (!this.httpBodyEncoding || this.httpBodyEncoding === "json") {
                            try {
                                bodyValue = JSON.parse(this.body);
                                contentType = "application/json";
                            } catch (e) {
                                throw new Error("Your JSON body is invalid. " + e.message);
                            }
                        } else if (this.httpBodyEncoding === "form") {
                            bodyValue = this.body;
                            contentType = "application/x-www-form-urlencoded";
                        } else if (this.httpBodyEncoding === "xml") {
                            bodyValue = this.body;
                            contentType = "text/xml; charset=utf-8";
                        }
                    }

                    // Axios Options
                    const options = {
                        url: this.url,
                        method: (this.method || "get").toLowerCase(),
                        timeout: this.timeout * 1000,
                        headers: {
                            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                            ...(contentType ? { "Content-Type": contentType } : {}),
                            ...(basicAuthHeader),
                            ...(oauth2AuthHeader),
                            ...(this.headers ? JSON.parse(this.headers) : {})
                        },
                        maxRedirects: this.maxredirects,
                        validateStatus: (status) => {
                            return checkStatusCode(status, this.getAcceptedStatuscodes());
                        },
                        signal: axiosAbortSignal((this.timeout + 10) * 1000),
                    };

                    if (bodyValue) {
                        options.data = bodyValue;
                    }

                    if (this.cacheBust) {
                        const randomFloatString = Math.random().toString(36);
                        const cacheBust = randomFloatString.substring(2);
                        options.params = {
                            uptime_kuma_cachebuster: cacheBust,
                        };
                    }

                    if (this.proxy_id) {
                        const proxy = await R.load("proxy", this.proxy_id);

                        if (proxy && proxy.active) {
                            const { httpAgent, httpsAgent } = Proxy.createAgents(proxy, {
                                httpsAgentOptions: httpsAgentOptions,
                                httpAgentOptions: httpAgentOptions,
                            });

                            options.proxy = false;
                            options.httpAgent = httpAgent;
                            options.httpsAgent = httpsAgent;
                        }
                    }

                    if (!options.httpAgent) {
                        options.httpAgent = new http.Agent(httpAgentOptions);
                    }

                    if (!options.httpsAgent) {
                        let jar = new CookieJar();
                        let httpsCookieAgentOptions = {
                            ...httpsAgentOptions,
                            cookies: { jar }
                        };
                        options.httpsAgent = new HttpsCookieAgent(httpsCookieAgentOptions);
                    }

                    if (this.auth_method === "mtls") {
                        if (this.tlsCert !== null && this.tlsCert !== "") {
                            options.httpsAgent.options.cert = Buffer.from(this.tlsCert);
                        }
                        if (this.tlsCa !== null && this.tlsCa !== "") {
                            options.httpsAgent.options.ca = Buffer.from(this.tlsCa);
                        }
                        if (this.tlsKey !== null && this.tlsKey !== "") {
                            options.httpsAgent.options.key = Buffer.from(this.tlsKey);
                        }
                    }

                    let tlsInfo = {};
                    // Store tlsInfo when secureConnect event is emitted
                    // The keylog event listener is a workaround to access the tlsSocket
                    options.httpsAgent.once("keylog", async (line, tlsSocket) => {
                        tlsSocket.once("secureConnect", async () => {
                            tlsInfo = checkCertificate(tlsSocket);
                            tlsInfo.valid = tlsSocket.authorized || false;
                            tlsInfo.hostnameMatchMonitorUrl = checkCertificateHostname(tlsInfo.certInfo.raw, this.getUrl()?.hostname);

                            await this.handleTlsInfo(tlsInfo);
                        });
                    });

                    log.debug("monitor", `[${this.name}] Axios Options: ${JSON.stringify(options)}`);
                    log.debug("monitor", `[${this.name}] Axios Request`);

                    // Make Request
                    let res = await this.makeAxiosRequest(options);

                    bean.msg = `${res.status} - ${res.statusText}`;
                    bean.ping = dayjs().valueOf() - startTime;

                    // fallback for if kelog event is not emitted, but we may still have tlsInfo,
                    // e.g. if the connection is made through a proxy
                    if (this.getUrl()?.protocol === "https:" && tlsInfo.valid === undefined) {
                        const tlsSocket = res.request.res.socket;

                        if (tlsSocket) {
                            tlsInfo = checkCertificate(tlsSocket);
                            tlsInfo.valid = tlsSocket.authorized || false;
                            tlsInfo.hostnameMatchMonitorUrl = checkCertificateHostname(tlsInfo.certInfo.raw, this.getUrl()?.hostname);

                            await this.handleTlsInfo(tlsInfo);
                        }
                    }

                    // eslint-disable-next-line eqeqeq
                    if (process.env.UPTIME_KUMA_LOG_RESPONSE_BODY_MONITOR_ID == this.id) {
                        log.info("monitor", res.data);
                    }

                    if (this.type === "http") {
                        bean.status = UP;
                    } else if (this.type === "keyword") {

                        let data = res.data;

                        // Convert to string for object/array
                        if (typeof data !== "string") {
                            data = JSON.stringify(data);
                        }

                        let keywordFound = data.includes(this.keyword);
                        if (keywordFound === !this.isInvertKeyword()) {
                            bean.msg += ", keyword " + (keywordFound ? "is" : "not") + " found";
                            bean.status = UP;
                        } else {
                            data = data.replace(/<[^>]*>?|[\n\r]|\s+/gm, " ").trim();
                            if (data.length > 50) {
                                data = data.substring(0, 47) + "...";
                            }
                            throw new Error(bean.msg + ", but keyword is " +
                                (keywordFound ? "present" : "not") + " in [" + data + "]");
                        }

                    } else if (this.type === "json-query") {
                        let data = res.data;

                        const { status, response } = await evaluateJsonQuery(data, this.jsonPath, this.jsonPathOperator, this.expectedValue);

                        if (status) {
                            bean.status = UP;
                            bean.msg = `JSON query passes (comparing ${response} ${this.jsonPathOperator} ${this.expectedValue})`;
                        } else {
                            throw new Error(`JSON query does not pass (comparing ${response} ${this.jsonPathOperator} ${this.expectedValue})`);
                        }

                    }

                } else if (this.type === "ping") {
                    bean.ping = await ping(this.hostname, this.ping_count, "", this.ping_numeric, this.packetSize, this.timeout, this.ping_per_request_timeout);
                    bean.msg = "";
                    bean.status = UP;
                } else if (this.type === "push") {      // Type: Push
                    log.debug("monitor", `[${this.name}] Checking monitor at ${dayjs().format("YYYY-MM-DD HH:mm:ss.SSS")}`);
                    const bufferTime = 1000; // 1s buffer to accommodate clock differences

                    if (previousBeat) {
                        const msSinceLastBeat = dayjs.utc().valueOf() - dayjs.utc(previousBeat.time).valueOf();

                        log.debug("monitor", `[${this.name}] msSinceLastBeat = ${msSinceLastBeat}`);

                        // If the previous beat was down or pending we use the regular
                        // beatInterval/retryInterval in the setTimeout further below
                        if (previousBeat.status !== (this.isUpsideDown() ? DOWN : UP) || msSinceLastBeat > beatInterval * 1000 + bufferTime) {
                            bean.duration = Math.round(msSinceLastBeat / 1000);
                            throw new Error("No heartbeat in the time window");
                        } else {
                            let timeout = beatInterval * 1000 - msSinceLastBeat;
                            if (timeout < 0) {
                                timeout = bufferTime;
                            } else {
                                timeout += bufferTime;
                            }
                            // No need to insert successful heartbeat for push type, so end here
                            retries = 0;
                            log.debug("monitor", `[${this.name}] timeout = ${timeout}`);
                            this.heartbeatInterval = setTimeout(safeBeat, timeout);
                            return;
                        }
                    } else {
                        bean.duration = beatInterval;
                        throw new Error("No heartbeat in the time window");
                    }

                } else if (this.type === "steam") {
                    const steamApiUrl = "https://api.steampowered.com/IGameServersService/GetServerList/v1/";
                    const steamAPIKey = await setting("steamAPIKey");
                    const filter = `addr\\${this.hostname}:${this.port}`;

                    if (!steamAPIKey) {
                        throw new Error("Steam API Key not found");
                    }

                    let res = await axios.get(steamApiUrl, {
                        timeout: this.timeout * 1000,
                        headers: {
                            "Accept": "*/*",
                        },
                        httpsAgent: new https.Agent({
                            maxCachedSessions: 0,      // Use Custom agent to disable session reuse (https://github.com/nodejs/node/issues/3940)
                            rejectUnauthorized: !this.getIgnoreTls(),
                            secureOptions: crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT,
                        }),
                        httpAgent: new http.Agent({
                            maxCachedSessions: 0,
                        }),
                        maxRedirects: this.maxredirects,
                        validateStatus: (status) => {
                            return checkStatusCode(status, this.getAcceptedStatuscodes());
                        },
                        params: {
                            filter: filter,
                            key: steamAPIKey,
                        }
                    });

                    if (res.data.response && res.data.response.servers && res.data.response.servers.length > 0) {
                        bean.status = UP;
                        bean.msg = res.data.response.servers[0].name;

                        try {
                            bean.ping = await ping(this.hostname, PING_COUNT_DEFAULT, "", true, this.packetSize, PING_GLOBAL_TIMEOUT_DEFAULT, PING_PER_REQUEST_TIMEOUT_DEFAULT);
                        } catch (_) { }
                    } else {
                        throw new Error("Server not found on Steam");
                    }
                } else if (this.type === "gamedig") {
                    try {
                        const state = await Gamedig.query({
                            type: this.game,
                            host: this.hostname,
                            port: this.port,
                            givenPortOnly: this.getGameDigGivenPortOnly(),
                        });

                        bean.msg = state.name;
                        bean.status = UP;
                        bean.ping = state.ping;
                    } catch (e) {
                        throw new Error(e.message);
                    }
                } else if (this.type === "docker") {
                    log.debug("monitor", `[${this.name}] Prepare Options for Axios`);

                    const options = {
                        url: `/containers/${this.docker_container}/json`,
                        timeout: this.interval * 1000 * 0.8,
                        headers: {
                            "Accept": "*/*",
                        },
                        httpsAgent: new https.Agent({
                            maxCachedSessions: 0,      // Use Custom agent to disable session reuse (https://github.com/nodejs/node/issues/3940)
                            rejectUnauthorized: !this.getIgnoreTls(),
                            secureOptions: crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT,
                        }),
                        httpAgent: new http.Agent({
                            maxCachedSessions: 0,
                        }),
                    };

                    const dockerHost = await R.load("docker_host", this.docker_host);

                    if (!dockerHost) {
                        throw new Error("Failed to load docker host config");
                    }

                    if (dockerHost._dockerType === "socket") {
                        options.socketPath = dockerHost._dockerDaemon;
                    } else if (dockerHost._dockerType === "tcp") {
                        options.baseURL = DockerHost.patchDockerURL(dockerHost._dockerDaemon);
                        options.httpsAgent = new https.Agent(
                            await DockerHost.getHttpsAgentOptions(dockerHost._dockerType, options.baseURL)
                        );
                    }

                    log.debug("monitor", `[${this.name}] Axios Request`);
                    let res = await axios.request(options);

                    if (res.data.State.Running) {
                        if (res.data.State.Health && res.data.State.Health.Status !== "healthy") {
                            bean.status = PENDING;
                            bean.msg = res.data.State.Health.Status;
                        } else {
                            bean.status = UP;
                            bean.msg = res.data.State.Health ? res.data.State.Health.Status : res.data.State.Status;
                        }
                    } else {
                        throw Error("Container State is " + res.data.State.Status);
                    }
                } else if (this.type === "sqlserver") {
                    let startTime = dayjs().valueOf();

                    await mssqlQuery(this.databaseConnectionString, this.databaseQuery || "SELECT 1");

                    bean.msg = "";
                    bean.status = UP;
                    bean.ping = dayjs().valueOf() - startTime;
                } else if (this.type === "postgres") {
                    let startTime = dayjs().valueOf();

                    await postgresQuery(this.databaseConnectionString, this.databaseQuery || "SELECT 1");

                    bean.msg = "";
                    bean.status = UP;
                    bean.ping = dayjs().valueOf() - startTime;
                } else if (this.type === "mysql") {
                    let startTime = dayjs().valueOf();

                    // Use `radius_password` as `password` field, since there are too many unnecessary fields
                    // TODO: rename `radius_password` to `password` later for general use
                    let mysqlPassword = this.radiusPassword;

                    bean.msg = await mysqlQuery(this.databaseConnectionString, this.databaseQuery || "SELECT 1", mysqlPassword);
                    bean.status = UP;
                    bean.ping = dayjs().valueOf() - startTime;
                } else if (this.type === "radius") {
                    let startTime = dayjs().valueOf();

                    // Handle monitors that were created before the
                    // update and as such don't have a value for
                    // this.port.
                    let port;
                    if (this.port == null) {
                        port = 1812;
                    } else {
                        port = this.port;
                    }

                    const resp = await radius(
                        this.hostname,
                        this.radiusUsername,
                        this.radiusPassword,
                        this.radiusCalledStationId,
                        this.radiusCallingStationId,
                        this.radiusSecret,
                        port,
                        this.interval * 1000 * 0.4,
                    );

                    bean.msg = resp.code;
                    bean.status = UP;
                    bean.ping = dayjs().valueOf() - startTime;
                } else if (this.type in UptimeKumaServer.monitorTypeList) {
                    let startTime = dayjs().valueOf();
                    const monitorType = UptimeKumaServer.monitorTypeList[this.type];
                    await monitorType.check(this, bean, UptimeKumaServer.getInstance());

                    if (!monitorType.allowCustomStatus && bean.status !== UP) {
                        throw new Error("The monitor implementation is incorrect, non-UP error must throw error inside check()");
                    }

                    if (!bean.ping) {
                        bean.ping = dayjs().valueOf() - startTime;
                    }

                } else if (this.type === "kafka-producer") {
                    let startTime = dayjs().valueOf();

                    bean.msg = await kafkaProducerAsync(
                        JSON.parse(this.kafkaProducerBrokers),
                        this.kafkaProducerTopic,
                        this.kafkaProducerMessage,
                        {
                            allowAutoTopicCreation: this.kafkaProducerAllowAutoTopicCreation,
                            ssl: this.kafkaProducerSsl,
                            clientId: `Uptime-Kuma/${version}`,
                            interval: this.interval,
                        },
                        JSON.parse(this.kafkaProducerSaslOptions),
                    );
                    bean.status = UP;
                    bean.ping = dayjs().valueOf() - startTime;

                } else {
                    throw new Error("Unknown Monitor Type");
                }

                if (this.isUpsideDown()) {
                    bean.status = flipStatus(bean.status);

                    if (bean.status === DOWN) {
                        throw new Error("Flip UP to DOWN");
                    }
                }

                retries = 0;

            } catch (error) {

                if (error?.name === "CanceledError") {
                    bean.msg = `timeout by AbortSignal (${this.timeout}s)`;
                } else {
                    bean.msg = error.message;
                }

                // Handle upside down mode: when service is actually UP, it's flipped to DOWN
                // and an error "Flip UP to DOWN" is thrown. We need to handle this case.
                if (this.isUpsideDown() && error.message === "Flip UP to DOWN") {
                    // Service is actually UP, but we want to show it as DOWN in upside down mode
                    bean.status = DOWN;
                    retries = 0;
                } else if (this.isUpsideDown() && bean.status === UP) {
                    // If UP come in here, it must be upside down mode
                    // Just reset the retries
                    retries = 0;

                } else if ((this.maxretries > 0) && (retries < this.maxretries)) {
                    retries++;
                    bean.status = PENDING;
                } else {
                    // Continue counting retries during DOWN
                    retries++;
                    // Ensure status is set to DOWN if not already set
                    if (bean.status !== PENDING && bean.status !== MAINTENANCE) {
                        bean.status = DOWN;
                    }
                }
            }

            bean.retries = retries;

            log.debug("monitor", `[${this.name}] Check isImportant`);
            let isImportant = Monitor.isImportantBeat(isFirstBeat, previousBeat?.status, bean.status);

            // Mark as important if status changed, ignore pending pings,
            // Don't notify if disrupted changes to up
            if (isImportant) {
                bean.important = true;

                if (Monitor.isImportantForNotification(isFirstBeat, previousBeat?.status, bean.status)) {
                    log.debug("monitor", `[${this.name}] sendNotification`);
                    try {
                        await Monitor.sendNotification(isFirstBeat, this, bean, null, previousBeat?.status);
                    } catch (e) {
                        // Don't let notification errors prevent heartbeat from being sent
                        log.error("monitor", `[${this.name}] Failed to send notification: ${e.message}`);
                        log.error("monitor", e);
                    }
                    // log.debug("monitor", `[${this.name}] sendNotification (skipped in dev)`);
                } else {
                    log.debug("monitor", `[${this.name}] will not sendNotification because it is (or was) under maintenance`);
                }

                // Reset down count
                bean.downCount = 0;

                // Clear Status Page Cache
                log.debug("monitor", `[${this.name}] apicache clear`);
                apicache.clear();

                await UptimeKumaServer.getInstance().sendMaintenanceListByUserID(this.user_id);

            } else {
                bean.important = false;

                if (bean.status === DOWN) {
                    // Check if we should send notification based on resendInterval
                    if (this.resendInterval > 0) {
                        // IMPORTANT: When resendInterval > 0, notification rules are NOT used!
                        // Only the old resendInterval mechanism (send notification every N heartbeats) is used.
                        // If you want to use notification rules (e.g., 60s/120s thresholds), set resendInterval = 0
                        if (this.notification_rules) {
                            log.debug("monitor", `[${this.name}] resendInterval=${this.resendInterval} > 0, notification rules will NOT be used. Set resendInterval=0 to enable time-based notification rules.`);
                        }
                        ++bean.downCount;
                        if (bean.downCount >= this.resendInterval) {
                            // Send notification again, because we are still DOWN
                            log.debug("monitor", `[${this.name}] sendNotification again: Down Count: ${bean.downCount} | Resend Interval: ${this.resendInterval}`);
                            try {
                                await Monitor.sendNotification(isFirstBeat, this, bean);
                            } catch (e) {
                                // Don't let notification errors prevent heartbeat from being sent
                                log.error("monitor", `[${this.name}] Failed to send notification: ${e.message}`);
                                log.error("monitor", e);
                            }

                            // Reset down count
                            bean.downCount = 0;
                        }
                    } else {
                        // If resendInterval is 0, check notification rules to see if we should send notification
                        // based on down duration thresholds
                        // IMPORTANT: Notification rules only work when resendInterval = 0
                        // If resendInterval > 0, the old resendInterval mechanism is used instead
                        let notificationRules = null;
                        
                        // Try to load notification rules from database if not already loaded
                        if (!this.notification_rules) {
                            const rules = await Monitor.getMonitorNotificationRules([this.id]);
                            if (rules && rules.length > 0) {
                                notificationRules = rules;
                            }
                        } else {
                            try {
                                notificationRules = JSON.parse(this.notification_rules);
                            } catch (e) {
                                log.error("monitor", `Failed to parse notification_rules for monitor ${this.id}: ${e.message}`);
                                // Fallback: try loading from database
                                const rules = await Monitor.getMonitorNotificationRules([this.id]);
                                if (rules && rules.length > 0) {
                                    notificationRules = rules;
                                }
                            }
                        }

                        if (notificationRules && Array.isArray(notificationRules) && notificationRules.length > 0) {
                            // Filter out inactive rules
                            const activeRules = notificationRules.filter(rule => rule.active !== false);
                            if (activeRules.length === 0) {
                                log.debug("monitor", `[${this.name}] All notification rules are inactive, skipping rule-based notifications`);
                            } else {
                                const downDuration = await Monitor.getDownDuration(this.id, bean);
                                if (downDuration !== null) {
                                    // Sort rules by duration (ascending) - shortest duration first
                                    const sortedRules = [...activeRules].sort((a, b) => (a.duration || a.delay || 0) - (b.duration || b.delay || 0));
                                    
                                    const previousDownDuration = previousBeat ? await Monitor.getDownDuration(this.id, previousBeat) : null;
                                    
                                    log.debug("monitor", `[${this.name}] Checking notification rules: downDuration=${downDuration}s, previousDownDuration=${previousDownDuration}s, rules=${sortedRules.map(r => r.duration || r.delay || 0).join(',')}s`);
                                    
                                    // Check ALL rules that should be triggered (not just the highest one)
                                    // This ensures that:
                                    // 1. Rule with 30s duration triggers at 30s
                                    // 2. Rule with 60s duration triggers at 60s
                                    // 3. Rule with 90s duration triggers at 90s
                                    // Each rule triggers when its threshold is reached
                                    for (const rule of sortedRules) {
                                        const ruleDuration = rule.duration || rule.delay || 0;
                                        
                                        // Skip if this rule's duration hasn't been reached yet
                                        if (downDuration < ruleDuration) {
                                            log.debug("monitor", `[${this.name}] Rule duration=${ruleDuration}s not reached yet (downDuration=${downDuration}s)`);
                                            continue;
                                        }
                                        
                                        // Check if we've just reached or crossed this rule's threshold
                                        // This means: current downDuration >= rule.duration, but previous was < rule.duration
                                        const justReachedThreshold = (previousDownDuration === null || previousDownDuration < ruleDuration) &&
                                            downDuration >= ruleDuration;
                                        
                                        log.debug("monitor", `[${this.name}] Rule duration=${ruleDuration}s: downDuration=${downDuration}s, previousDownDuration=${previousDownDuration}s, justReachedThreshold=${justReachedThreshold}`);
                                        
                                        if (justReachedThreshold) {
                                            // Get the notification list for this specific rule
                                            let ruleNotificationList = [];
                                            
                                            // Support multiple formats for notification IDs
                                            let notificationIdsToUse = [];
                                            if (rule.notificationIDList && typeof rule.notificationIDList === 'object') {
                                                notificationIdsToUse = Object.keys(rule.notificationIDList).filter(id => rule.notificationIDList[id]);
                                            } else if (rule.notificationIds && Array.isArray(rule.notificationIds)) {
                                                notificationIdsToUse = rule.notificationIds;
                                            } else if (rule.notificationId !== null && rule.notificationId !== undefined) {
                                                notificationIdsToUse = [rule.notificationId];
                                            }

                                            if (notificationIdsToUse.length > 0) {
                                                const placeholders = notificationIdsToUse.map(() => '?').join(',');
                                                ruleNotificationList = await R.getAll(
                                                    `SELECT notification.* FROM notification, monitor_notification 
                                                    WHERE monitor_id = ? 
                                                    AND monitor_notification.notification_id = notification.id 
                                                    AND notification.id IN (${placeholders})`,
                                                    [this.id, ...notificationIdsToUse]
                                                );
                                                log.debug("monitor", `[${this.name}] Rule notification list: ${ruleNotificationList.length} notification(s) for rule duration=${ruleDuration}s`);
                                            }

                                            if (ruleNotificationList.length > 0) {
                                                log.debug("monitor", `[${this.name}] sendNotification based on rule threshold: duration=${ruleDuration}s, downDuration=${downDuration}s, notifications=${notificationIdsToUse.join(',')}`);
                                                try {
                                                    await Monitor.sendNotification(isFirstBeat, this, bean, ruleNotificationList);
                                                } catch (e) {
                                                    log.error("monitor", `[${this.name}] Failed to send notification: ${e.message}`);
                                                    log.error("monitor", e);
                                                }
                                            } else {
                                                log.warn("monitor", `[${this.name}] Rule matched but no valid notifications found for rule duration=${ruleDuration}s`);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if (bean.status === UP) {
                log.debug("monitor", `Monitor #${this.id} '${this.name}': Successful Response: ${bean.ping} ms | Interval: ${beatInterval} seconds | Type: ${this.type}`);
            } else if (bean.status === PENDING) {
                if (this.retryInterval > 0) {
                    beatInterval = this.retryInterval;
                }
                log.warn("monitor", `Monitor #${this.id} '${this.name}': Pending: ${bean.msg} | Max retries: ${this.maxretries} | Retry: ${retries} | Retry Interval: ${beatInterval} seconds | Type: ${this.type}`);
            } else if (bean.status === MAINTENANCE) {
                log.warn("monitor", `Monitor #${this.id} '${this.name}': Under Maintenance | Type: ${this.type}`);
            } else {
                log.warn("monitor", `Monitor #${this.id} '${this.name}': Failing: ${bean.msg} | Interval: ${beatInterval} seconds | Type: ${this.type} | Down Count: ${bean.downCount} | Resend Interval: ${this.resendInterval}`);
            }

            // Calculate uptime
            let uptimeCalculator = await UptimeCalculator.getUptimeCalculator(this.id);
            let endTimeDayjs = await uptimeCalculator.update(bean.status, parseFloat(bean.ping));
            bean.end_time = R.isoDateTimeMillis(endTimeDayjs);

            // Send to frontend
            log.debug("monitor", `[${this.name}] Send to socket`);
            io.to(this.user_id).emit("heartbeat", bean.toJSON());
            Monitor.sendStats(io, this.id, this.user_id);

            // Store to database
            log.debug("monitor", `[${this.name}] Store`);
            await R.store(bean);

            log.debug("monitor", `[${this.name}] prometheus.update`);
            this.prometheus?.update(bean, tlsInfo);

            previousBeat = bean;

            if (! this.isStop) {
                log.debug("monitor", `[${this.name}] SetTimeout for next check.`);

                let intervalRemainingMs = Math.max(
                    1,
                    beatInterval * 1000 - dayjs().diff(dayjs.utc(bean.time))
                );

                log.debug("monitor", `[${this.name}] Next heartbeat in: ${intervalRemainingMs}ms`);

                this.heartbeatInterval = setTimeout(safeBeat, intervalRemainingMs);
            } else {
                log.info("monitor", `[${this.name}] isStop = true, no next check.`);
            }

        };

        /**
         * Get a heartbeat and handle errors7
         * @returns {void}
         */
        const safeBeat = async () => {
            try {
                await beat();
            } catch (e) {
                console.trace(e);
                UptimeKumaServer.errorLog(e, false);
                log.error("monitor", "Please report to https://github.com/louislam/uptime-kuma/issues");

                if (! this.isStop) {
                    log.info("monitor", "Try to restart the monitor");
                    this.heartbeatInterval = setTimeout(safeBeat, this.interval * 1000);
                }
            }
        };

        // Delay Push Type
        if (this.type === "push") {
            setTimeout(() => {
                safeBeat();
            }, this.interval * 1000);
        } else {
            safeBeat();
        }
    }

    /**
     * Make a request using axios
     * @param {object} options Options for Axios
     * @param {boolean} finalCall Should this be the final call i.e
     * don't retry on failure
     * @returns {object} Axios response
     */
    async makeAxiosRequest(options, finalCall = false) {
        try {
            let res;
            if (this.auth_method === "ntlm") {
                options.httpsAgent.keepAlive = true;

                res = await httpNtlm(options, {
                    username: this.basic_auth_user,
                    password: this.basic_auth_pass,
                    domain: this.authDomain,
                    workstation: this.authWorkstation ? this.authWorkstation : undefined
                });
            } else {
                res = await axios.request(options);
            }

            return res;
        } catch (error) {

            /**
             * Make a single attempt to obtain an new access token in the event that
             * the recent api request failed for authentication purposes
             */
            if (this.auth_method === "oauth2-cc" && error.response.status === 401 && !finalCall) {
                this.oauthAccessToken = await this.makeOidcTokenClientCredentialsRequest();
                let oauth2AuthHeader = {
                    "Authorization": this.oauthAccessToken.token_type + " " + this.oauthAccessToken.access_token,
                };
                options.headers = { ...(options.headers),
                    ...(oauth2AuthHeader)
                };

                return this.makeAxiosRequest(options, true);
            }

            // Fix #2253
            // Read more: https://stackoverflow.com/questions/1759956/curl-error-18-transfer-closed-with-outstanding-read-data-remaining
            if (!finalCall && typeof error.message === "string" && error.message.includes("maxContentLength size of -1 exceeded")) {
                log.debug("monitor", "makeAxiosRequest with gzip");
                options.headers["Accept-Encoding"] = "gzip, deflate";
                return this.makeAxiosRequest(options, true);
            } else {
                if (typeof error.message === "string" && error.message.includes("maxContentLength size of -1 exceeded")) {
                    error.message = "response timeout: incomplete response within a interval";
                }
                
                // Improve error message for SSL/TLS protocol errors
                if (error.code === "EPROTO" || (typeof error.message === "string" && error.message.includes("wrong version number"))) {
                    const url = new URL(options.url);
                    if (url.protocol === "https:") {
                        error.message = `SSL/TLS error: The server at ${url.hostname}${url.port ? ":" + url.port : ""} may not support HTTPS. Try using http:// instead of https://`;
                    } else {
                        error.message = `SSL/TLS error: ${error.message}`;
                    }
                }
                
                throw error;
            }
        }
    }

    /**
     * Stop monitor
     * @returns {Promise<void>}
     */
    async stop() {
        clearTimeout(this.heartbeatInterval);
        this.isStop = true;

        this.prometheus?.remove();
    }

    /**
     * Get prometheus instance
     * @returns {Prometheus|undefined} Current prometheus instance
     */
    getPrometheus() {
        return this.prometheus;
    }

    /**
     * Helper Method:
     * returns URL object for further usage
     * returns null if url is invalid
     * @returns {(null|URL)} Monitor URL
     */
    getUrl() {
        try {
            return new URL(this.url);
        } catch (_) {
            return null;
        }
    }

    /**
     * Example: http: or https:
     * @returns {(null|string)} URL's protocol
     */
    getURLProtocol() {
        const url = this.getUrl();
        if (url) {
            return this.getUrl().protocol;
        } else {
            return null;
        }
    }

    /**
     * Store TLS info to database
     * @param {object} checkCertificateResult Certificate to update
     * @returns {Promise<object>} Updated certificate
     */
    async updateTlsInfo(checkCertificateResult) {
        let tlsInfoBean = await R.findOne("monitor_tls_info", "monitor_id = ?", [
            this.id,
        ]);

        if (tlsInfoBean == null) {
            tlsInfoBean = R.dispense("monitor_tls_info");
            tlsInfoBean.monitor_id = this.id;
        } else {

            // Clear sent history if the cert changed.
            try {
                let oldCertInfo = JSON.parse(tlsInfoBean.info_json);

                let isValidObjects = oldCertInfo && oldCertInfo.certInfo && checkCertificateResult && checkCertificateResult.certInfo;

                if (isValidObjects) {
                    if (oldCertInfo.certInfo.fingerprint256 !== checkCertificateResult.certInfo.fingerprint256) {
                        log.debug("monitor", "Resetting sent_history");
                        await R.exec("DELETE FROM notification_sent_history WHERE type = 'certificate' AND monitor_id = ?", [
                            this.id
                        ]);
                    } else {
                        log.debug("monitor", "No need to reset sent_history");
                        log.debug("monitor", oldCertInfo.certInfo.fingerprint256);
                        log.debug("monitor", checkCertificateResult.certInfo.fingerprint256);
                    }
                } else {
                    log.debug("monitor", "Not valid object");
                }
            } catch (e) { }

        }

        tlsInfoBean.info_json = JSON.stringify(checkCertificateResult);
        await R.store(tlsInfoBean);

        return checkCertificateResult;
    }

    /**
     * Checks if the monitor is active based on itself and its parents
     * @param {number} monitorID ID of monitor to send
     * @param {boolean} active is active
     * @returns {Promise<boolean>} Is the monitor active?
     */
    static async isActive(monitorID, active) {
        const parentActive = await Monitor.isParentActive(monitorID);

        return (active === 1) && parentActive;
    }

    /**
     * Send statistics to clients
     * @param {Server} io Socket server instance
     * @param {number} monitorID ID of monitor to send
     * @param {number} userID ID of user to send to
     * @returns {void}
     */
    static async sendStats(io, monitorID, userID) {
        const hasClients = getTotalClientInRoom(io, userID) > 0;
        let uptimeCalculator = await UptimeCalculator.getUptimeCalculator(monitorID);

        if (hasClients) {
            // Send 24 hour average ping
            let data24h = await uptimeCalculator.get24Hour();
            io.to(userID).emit("avgPing", monitorID, (data24h.avgPing) ? Number(data24h.avgPing.toFixed(2)) : null);

            // Send 24 hour uptime
            io.to(userID).emit("uptime", monitorID, 24, data24h.uptime);

            // Send 30 day uptime
            let data30d = await uptimeCalculator.get30Day();
            io.to(userID).emit("uptime", monitorID, 720, data30d.uptime);

            // Send 1-year uptime
            let data1y = await uptimeCalculator.get1Year();
            io.to(userID).emit("uptime", monitorID, "1y", data1y.uptime);

            // Send Cert Info
            await Monitor.sendCertInfo(io, monitorID, userID);
        } else {
            log.debug("monitor", "No clients in the room, no need to send stats");
        }
    }

    /**
     * Send certificate information to client
     * @param {Server} io Socket server instance
     * @param {number} monitorID ID of monitor to send
     * @param {number} userID ID of user to send to
     * @returns {void}
     */
    static async sendCertInfo(io, monitorID, userID) {
        let tlsInfo = await R.findOne("monitor_tls_info", "monitor_id = ?", [
            monitorID,
        ]);
        if (tlsInfo != null) {
            io.to(userID).emit("certInfo", monitorID, tlsInfo.info_json);
        }
    }

    /**
     * Has status of monitor changed since last beat?
     * @param {boolean} isFirstBeat Is this the first beat of this monitor?
     * @param {const} previousBeatStatus Status of the previous beat
     * @param {const} currentBeatStatus Status of the current beat
     * @returns {boolean} True if is an important beat else false
     */
    static isImportantBeat(isFirstBeat, previousBeatStatus, currentBeatStatus) {
        // * ? -> ANY STATUS = important [isFirstBeat]
        // UP -> PENDING = not important
        // * UP -> DOWN = important
        // UP -> UP = not important
        // PENDING -> PENDING = not important
        // * PENDING -> DOWN = important
        // PENDING -> UP = not important
        // DOWN -> PENDING = this case not exists
        // DOWN -> DOWN = not important
        // * DOWN -> UP = important
        // MAINTENANCE -> MAINTENANCE = not important
        // * MAINTENANCE -> UP = important
        // * MAINTENANCE -> DOWN = important
        // * DOWN -> MAINTENANCE = important
        // * UP -> MAINTENANCE = important
        return isFirstBeat ||
            (previousBeatStatus === DOWN && currentBeatStatus === MAINTENANCE) ||
            (previousBeatStatus === UP && currentBeatStatus === MAINTENANCE) ||
            (previousBeatStatus === MAINTENANCE && currentBeatStatus === DOWN) ||
            (previousBeatStatus === MAINTENANCE && currentBeatStatus === UP) ||
            (previousBeatStatus === UP && currentBeatStatus === DOWN) ||
            (previousBeatStatus === DOWN && currentBeatStatus === UP) ||
            (previousBeatStatus === PENDING && currentBeatStatus === DOWN);
    }

    /**
     * Is this beat important for notifications?
     * @param {boolean} isFirstBeat Is this the first beat of this monitor?
     * @param {const} previousBeatStatus Status of the previous beat
     * @param {const} currentBeatStatus Status of the current beat
     * @returns {boolean} True if is an important beat else false
     */
    static isImportantForNotification(isFirstBeat, previousBeatStatus, currentBeatStatus) {
        // * ? -> ANY STATUS = important [isFirstBeat]
        // UP -> PENDING = not important
        // * UP -> DOWN = important
        // UP -> UP = not important
        // PENDING -> PENDING = not important
        // * PENDING -> DOWN = important
        // PENDING -> UP = not important
        // DOWN -> PENDING = this case not exists
        // DOWN -> DOWN = not important
        // * DOWN -> UP = important
        // MAINTENANCE -> MAINTENANCE = not important
        // MAINTENANCE -> UP = not important
        // * MAINTENANCE -> DOWN = important
        // DOWN -> MAINTENANCE = not important
        // UP -> MAINTENANCE = not important
        return isFirstBeat ||
            (previousBeatStatus === MAINTENANCE && currentBeatStatus === DOWN) ||
            (previousBeatStatus === UP && currentBeatStatus === DOWN) ||
            (previousBeatStatus === DOWN && currentBeatStatus === UP) ||
            (previousBeatStatus === PENDING && currentBeatStatus === DOWN);
    }

    /**
     * Send a notification about a monitor
     * @param {boolean} isFirstBeat Is this beat the first of this monitor?
     * @param {Monitor} monitor The monitor to send a notification about
     * @param {Bean} bean Status information about monitor
     * @param {Array|null} overrideNotificationList Optional: override notification list (e.g., from notification rules)
     * @returns {void}
     */
    /**
     * Send a notification about a monitor
     * @param {boolean} isFirstBeat Is this beat the first of this monitor?
     * @param {Monitor} monitor The monitor to send a notification about
     * @param {Bean} bean Status information about monitor
     * @param {Array|null} overrideNotificationList Optional: override notification list (e.g., from notification rules)
     * @param {number|null} previousBeatStatus Optional: previous beat status (for determining if this is an important beat)
     * @returns {void}
     */
    static async sendNotification(isFirstBeat, monitor, bean, overrideNotificationList = null, previousBeatStatus = null) {
        if (!isFirstBeat || bean.status === DOWN) {
            // Check if this is an important beat (status change like UP -> DOWN)
            // Use bean.important if available, otherwise calculate from previousBeatStatus
            const isImportantBeat = bean.important !== undefined ? bean.important : Monitor.isImportantForNotification(isFirstBeat, previousBeatStatus, bean.status);
            const notificationList = overrideNotificationList || await Monitor.getNotificationList(monitor, bean, isImportantBeat);
            
            log.debug("monitor", `[${monitor.name}] sendNotification: isFirstBeat=${isFirstBeat}, status=${bean.status}, notificationCount=${notificationList.length}, override=${overrideNotificationList !== null}`);

            if (notificationList.length === 0) {
                log.warn("monitor", `[${monitor.name}] No notifications configured for this monitor`);
                return;
            }

            let text;
            if (bean.status === UP) {
                text = "✅ Up";
            } else {
                text = "🔴 Down";
            }

            // Get base URL for dashboard link
            const baseURL = await setting("primaryBaseURL");
            
            for (let notification of notificationList) {
                try {
                    const heartbeatJSON = bean.toJSON();
                    const monitorData = [{ id: monitor.id,
                        active: monitor.active,
                        name: monitor.name
                    }];
                    const preloadData = await Monitor.preparePreloadData(monitorData);
                    // Prevent if the msg is undefined, notifications such as Discord cannot send out.
                    if (!heartbeatJSON["msg"]) {
                        heartbeatJSON["msg"] = "N/A";
                    }

                    // Also provide the time in server timezone
                    heartbeatJSON["timezone"] = await UptimeKumaServer.getInstance().getTimezone();
                    heartbeatJSON["timezoneOffset"] = UptimeKumaServer.getInstance().getTimezoneOffset();
                    heartbeatJSON["localDateTime"] = dayjs.utc(heartbeatJSON["time"]).tz(heartbeatJSON["timezone"]).format(SQL_DATETIME_FORMAT);

                    // Build message with monitor URL and notification time
                    let msg = `[${monitor.name}] [${text}] ${bean.msg}`;
                    
                    // Get monitor URL/address for the notification
                    const monitorJSON = monitor.toJSON(preloadData, false);
                    let monitorUrl = null;
                    
                    // Extract monitor URL/address based on monitor type
                    if (monitor.type === "http" || monitor.type === "keyword" || monitor.type === "json-query" || monitor.type === "real-browser") {
                        monitorUrl = monitor.url || monitor.customUrl;
                    } else if (monitor.type === "ping") {
                        monitorUrl = monitor.hostname;
                    } else if (monitor.type === "port" || monitor.type === "dns" || monitor.type === "gamedig" || monitor.type === "steam") {
                        if (monitor.port) {
                            monitorUrl = `${monitor.hostname}:${monitor.port}`;
                        } else {
                            monitorUrl = monitor.hostname;
                        }
                    }
                    
                    // Add monitor URL if available
                    if (monitorUrl && monitorUrl !== "https://" && monitorUrl !== "http://" && monitorUrl !== "") {
                        // Format as clickable link if it's a valid URL
                        if (monitorUrl.startsWith("http://") || monitorUrl.startsWith("https://")) {
                            msg += `\n\n監測網址: ${monitorUrl}`;
                        } else {
                            msg += `\n\n監測網址: ${monitorUrl}`;
                        }
                    }
                    
                    // Add dashboard URL if available
                    if (baseURL) {
                        const dashboardUrl = baseURL + getMonitorRelativeURL(monitor.id);
                        msg += `\n\n監測連結: ${dashboardUrl}`;
                    }
                    
                    // Add notification time
                    msg += `\n通知時間: ${heartbeatJSON["localDateTime"]}${heartbeatJSON["timezone"] ? ` (${heartbeatJSON["timezone"]})` : ""}`;

                    await Notification.send(JSON.parse(notification.config), msg, monitor.toJSON(preloadData, false), heartbeatJSON);
                } catch (e) {
                    log.error("monitor", "Cannot send notification to " + notification.name);
                    log.error("monitor", e);
                }
            }
        }
    }

    /**
     * Get the first down heartbeat time for a monitor to calculate down duration
     * @param {number} monitorID ID of monitor
     * @param {Bean} currentBean Current heartbeat bean
     * @returns {Promise<number|null>} Duration in seconds since first down, or null if not down
     */
    static async getDownDuration(monitorID, currentBean) {
        if (currentBean.status !== DOWN) {
            return null;
        }

        // Ensure time is in string format for SQL query
        const timeStr = typeof currentBean.time === 'string' ? currentBean.time : String(currentBean.time);

        // Find the first down heartbeat in the current down sequence
        // We need to find the heartbeat where status changed from UP/PENDING to DOWN
        const firstDownHeartbeat = await R.findOne("heartbeat", 
            " monitor_id = ? AND time <= ? AND status = ? ORDER BY time ASC", 
            [monitorID, timeStr, DOWN]
        );

        if (!firstDownHeartbeat) {
            return null;
        }

        // Check if there's an UP heartbeat after this down heartbeat
        // If yes, this is not the start of current down sequence
        const firstDownTimeStr = typeof firstDownHeartbeat.time === 'string' ? firstDownHeartbeat.time : String(firstDownHeartbeat.time);
        const upAfterDown = await R.findOne("heartbeat",
            " monitor_id = ? AND time > ? AND time <= ? AND status = ? ORDER BY time ASC",
            [monitorID, firstDownTimeStr, timeStr, UP]
        );

        if (upAfterDown) {
            // There was an UP between firstDownHeartbeat and current, so current down started after upAfterDown
            // Find the first down after the last UP
            const upAfterDownTimeStr = typeof upAfterDown.time === 'string' ? upAfterDown.time : String(upAfterDown.time);
            const firstDownAfterUp = await R.findOne("heartbeat",
                " monitor_id = ? AND time > ? AND time <= ? AND status = ? ORDER BY time ASC",
                [monitorID, upAfterDownTimeStr, timeStr, DOWN]
            );

            if (firstDownAfterUp) {
                return dayjs(currentBean.time).diff(dayjs(firstDownAfterUp.time), "second");
            }
        }

        return dayjs(currentBean.time).diff(dayjs(firstDownHeartbeat.time), "second");
    }

    /**
     * Get list of notification providers for a given monitor
     * @param {Monitor} monitor Monitor to get notification providers for
     * @param {Bean|null} bean Current heartbeat bean (optional, for time-based notification rules)
     * @param {boolean} isImportantBeat Whether this is an important beat (e.g., UP -> DOWN transition)
     * @returns {Promise<LooseObject<any>[]>} List of notifications
     */
    static async getNotificationList(monitor, bean = null, isImportantBeat = false) {
        // Check if notification rules are configured
        let notificationRules = null;
        
        // Try to load notification rules from database if not already loaded
        if (!monitor.notification_rules) {
            const rules = await Monitor.getMonitorNotificationRules([monitor.id]);
            if (rules && rules.length > 0) {
                notificationRules = rules;
            }
        } else {
            try {
                notificationRules = JSON.parse(monitor.notification_rules);
            } catch (e) {
                log.error("monitor", `Failed to parse notification_rules for monitor ${monitor.id}: ${e.message}`);
                // Fallback: try loading from database
                const rules = await Monitor.getMonitorNotificationRules([monitor.id]);
                if (rules && rules.length > 0) {
                    notificationRules = rules;
                }
            }
        }

        // If notification rules are configured and we have a bean with DOWN status, use time-based routing
        if (notificationRules && Array.isArray(notificationRules) && notificationRules.length > 0 && bean && bean.status === DOWN) {
            // Filter out inactive rules
            const activeRules = notificationRules.filter(rule => rule.active !== false);
            if (activeRules.length === 0) {
                log.debug("monitor", `[${monitor.name}] All notification rules are inactive, using default notifications`);
            } else {
                const downDuration = await Monitor.getDownDuration(monitor.id, bean);
                
                log.debug("monitor", `[${monitor.name}] Notification rules check: downDuration=${downDuration}s, isImportantBeat=${isImportantBeat}, rules=${JSON.stringify(activeRules)}`);
                
                // Sort rules by duration (ascending) - shortest duration first
                const sortedRules = [...activeRules].sort((a, b) => (a.duration || a.delay || 0) - (b.duration || b.delay || 0));
                
                // When downDuration is null, 0, or very small (< 5 seconds) AND this is an important beat (UP -> DOWN),
                // use the rule with minimum duration
                // This ensures that when UP -> DOWN, we notify the notification channel with the smallest duration threshold
                // We use < 5 seconds threshold to handle cases where getDownDuration might return 1-2 seconds due to timing
                if (isImportantBeat && (downDuration === null || downDuration === 0 || downDuration < 5)) {
                    if (sortedRules.length > 0) {
                        const minDurationRule = sortedRules[0];
                        const minDuration = minDurationRule.duration || minDurationRule.delay || 0;
                        log.debug("monitor", `[${monitor.name}] downDuration is ${downDuration} (first time DOWN), using minimum duration rule: ${minDuration}s`);
                        
                        // Get notification list for the minimum duration rule
                        let notificationIdsToUse = [];
                        if (minDurationRule.notificationIDList && typeof minDurationRule.notificationIDList === 'object') {
                            notificationIdsToUse = Object.keys(minDurationRule.notificationIDList).filter(id => minDurationRule.notificationIDList[id]);
                        } else if (minDurationRule.notificationIds && Array.isArray(minDurationRule.notificationIds)) {
                            notificationIdsToUse = minDurationRule.notificationIds;
                        } else if (minDurationRule.notificationId !== null && minDurationRule.notificationId !== undefined) {
                            notificationIdsToUse = [minDurationRule.notificationId];
                        }
                        
                        if (notificationIdsToUse.length > 0) {
                            const placeholders = notificationIdsToUse.map(() => '?').join(',');
                            let notificationList = await R.getAll(
                                `SELECT notification.* FROM notification, monitor_notification 
                                WHERE monitor_id = ? 
                                AND monitor_notification.notification_id = notification.id 
                                AND notification.id IN (${placeholders})`,
                                [monitor.id, ...notificationIdsToUse]
                            );
                            log.debug("monitor", `[${monitor.name}] Returning ${notificationList.length} notification(s) from minimum duration rule (duration=${minDuration}s, notificationIds=${notificationIdsToUse.join(',')})`);
                            if (notificationList.length > 0) {
                                return notificationList;
                            }
                        }
                        log.debug("monitor", `[${monitor.name}] Minimum duration rule has no valid notifications, falling back to default`);
                    } else {
                        log.debug("monitor", `[${monitor.name}] downDuration is ${downDuration} (first time DOWN), but no active rules found, using default notifications`);
                    }
                } else if (downDuration > 0) {
                    // Only apply notification rules if downDuration > 0 (monitor has been DOWN for some time)
                    // Sort rules by duration (ascending) to find the matching rule
                    const sortedRules = [...activeRules].sort((a, b) => (a.duration || 0) - (b.duration || 0));
                    
                    // Find the rule that matches the current down duration
                    // Use the rule with the highest duration that is <= current down duration
                    let matchingRule = null;
                    for (const rule of sortedRules) {
                        if (downDuration >= (rule.duration || 0)) {
                            matchingRule = rule;
                        } else {
                            break;
                        }
                    }

                    if (matchingRule) {
                        log.debug("monitor", `[${monitor.name}] Matched notification rule: duration=${matchingRule.duration}s, downDuration=${downDuration}s`);
                        
                        // Support multiple formats:
                        // 1. notificationIDList (object with notification IDs as keys) - from database
                        // 2. notificationIds (array) - old format
                        // 3. notificationId (single value) - new format
                        let notificationIdsToUse = [];
                        
                        if (matchingRule.notificationIDList && typeof matchingRule.notificationIDList === 'object') {
                            // Format from database: { "1": true, "2": true }
                            notificationIdsToUse = Object.keys(matchingRule.notificationIDList).filter(id => matchingRule.notificationIDList[id]);
                        } else if (matchingRule.notificationIds && Array.isArray(matchingRule.notificationIds)) {
                            // Old format: array
                            notificationIdsToUse = matchingRule.notificationIds;
                        } else if (matchingRule.notificationId !== null && matchingRule.notificationId !== undefined) {
                            // New format: single notificationId
                            notificationIdsToUse = [matchingRule.notificationId];
                        }

                        if (notificationIdsToUse.length > 0) {
                            // Return only the notifications specified in the matching rule
                            // IMPORTANT: The notifications must also be bound to this monitor in monitor_notification table
                            const placeholders = notificationIdsToUse.map(() => '?').join(',');
                            let notificationList = await R.getAll(
                                `SELECT notification.* FROM notification, monitor_notification 
                                WHERE monitor_id = ? 
                                AND monitor_notification.notification_id = notification.id 
                                AND notification.id IN (${placeholders})`,
                                [monitor.id, ...notificationIdsToUse]
                            );
                            log.debug("monitor", `[${monitor.name}] Returning ${notificationList.length} notification(s) from rule (notificationIds=${notificationIdsToUse.join(',')})`);
                            if (notificationList.length === 0) {
                                log.warn("monitor", `[${monitor.name}] Rule matched but none of the notifications [${notificationIdsToUse.join(',')}] are bound to this monitor! Falling back to default notifications.`);
                            } else {
                                return notificationList;
                            }
                        } else {
                            log.debug("monitor", `[${monitor.name}] Matched rule but no notification IDs found, falling back to default behavior`);
                        }
                    } else {
                        // No matching rule found (e.g., downDuration = 5 but all rules require duration >= 60)
                        // Fall back to default notifications
                        log.debug("monitor", `[${monitor.name}] No matching rule found for downDuration=${downDuration}s (all rules require longer duration), falling back to default behavior`);
                    }
                }
                // If downDuration === 0, also fall through to default behavior
            }
        }

        // Default behavior: return all notifications bound to this monitor
        // This is used when:
        // 1. No notification rules are configured
        // 2. Status is UP (rules only apply to DOWN status)
        // 3. Status is DOWN but downDuration is null (first time DOWN)
        // 4. Status is DOWN but no rule matches the current downDuration
        let notificationList = await R.getAll("SELECT notification.* FROM notification, monitor_notification WHERE monitor_id = ? AND monitor_notification.notification_id = notification.id ", [
            monitor.id,
        ]);
        log.debug("monitor", `[${monitor.name}] Returning ${notificationList.length} default notification(s) for monitor`);
        if (notificationList.length === 0 && bean && bean.status === DOWN) {
            log.warn("monitor", `[${monitor.name}] WARNING: No notifications are bound to this monitor! Please add notifications in Monitor → Notifications tab.`);
        }
        return notificationList;
    }

    /**
     * checks certificate chain for expiring certificates
     * @param {object} tlsInfoObject Information about certificate
     * @returns {void}
     */
    async checkCertExpiryNotifications(tlsInfoObject) {
        if (tlsInfoObject && tlsInfoObject.certInfo && tlsInfoObject.certInfo.daysRemaining) {
            const notificationList = await Monitor.getNotificationList(this);

            if (! notificationList.length > 0) {
                // fail fast. If no notification is set, all the following checks can be skipped.
                log.debug("monitor", "No notification, no need to send cert notification");
                return;
            }

            let notifyDays = await setting("tlsExpiryNotifyDays");
            if (notifyDays == null || !Array.isArray(notifyDays)) {
                // Reset Default
                await setSetting("tlsExpiryNotifyDays", [ 7, 14, 21 ], "general");
                notifyDays = [ 7, 14, 21 ];
            }

            if (Array.isArray(notifyDays)) {
                for (const targetDays of notifyDays) {
                    let certInfo = tlsInfoObject.certInfo;
                    while (certInfo) {
                        let subjectCN = certInfo.subject["CN"];
                        if (rootCertificates.has(certInfo.fingerprint256)) {
                            log.debug("monitor", `Known root cert: ${certInfo.certType} certificate "${subjectCN}" (${certInfo.daysRemaining} days valid) on ${targetDays} deadline.`);
                            break;
                        } else if (certInfo.daysRemaining > targetDays) {
                            log.debug("monitor", `No need to send cert notification for ${certInfo.certType} certificate "${subjectCN}" (${certInfo.daysRemaining} days valid) on ${targetDays} deadline.`);
                        } else {
                            log.debug("monitor", `call sendCertNotificationByTargetDays for ${targetDays} deadline on certificate ${subjectCN}.`);
                            await this.sendCertNotificationByTargetDays(subjectCN, certInfo.certType, certInfo.daysRemaining, targetDays, notificationList);
                        }
                        certInfo = certInfo.issuerCertificate;
                    }
                }
            }
        }
    }

    /**
     * Send a certificate notification when certificate expires in less
     * than target days
     * @param {string} certCN  Common Name attribute from the certificate subject
     * @param {string} certType  certificate type
     * @param {number} daysRemaining Number of days remaining on certificate
     * @param {number} targetDays Number of days to alert after
     * @param {LooseObject<any>[]} notificationList List of notification providers
     * @returns {Promise<void>}
     */
    async sendCertNotificationByTargetDays(certCN, certType, daysRemaining, targetDays, notificationList) {

        let row = await R.getRow("SELECT * FROM notification_sent_history WHERE type = ? AND monitor_id = ? AND days <= ?", [
            "certificate",
            this.id,
            targetDays,
        ]);

        // Sent already, no need to send again
        if (row) {
            log.debug("monitor", "Sent already, no need to send again");
            return;
        }

        let sent = false;
        log.debug("monitor", "Send certificate notification");

        // Get base URL for dashboard link
        const baseURL = await setting("primaryBaseURL");
        const currentTime = dayjs().tz(await UptimeKumaServer.getInstance().getTimezone()).format(SQL_DATETIME_FORMAT);
        const timezone = await UptimeKumaServer.getInstance().getTimezone();

        for (let notification of notificationList) {
            try {
                log.debug("monitor", "Sending to " + notification.name);
                await Notification.send(JSON.parse(notification.config), `[${this.name}][${this.url}] ${certType} certificate ${certCN} will expire in ${daysRemaining} days`);
                sent = true;
            } catch (e) {
                log.error("monitor", "Cannot send cert notification to " + notification.name);
                log.error("monitor", e);
            }
        }

        if (sent) {
            await R.exec("INSERT INTO notification_sent_history (type, monitor_id, days) VALUES(?, ?, ?)", [
                "certificate",
                this.id,
                targetDays,
            ]);
        }
    }

    /**
     * Get the status of the previous heartbeat
     * @param {number} monitorID ID of monitor to check
     * @returns {Promise<LooseObject<any>>} Previous heartbeat
     */
    static async getPreviousHeartbeat(monitorID) {
        return await R.findOne("heartbeat", " id = (select MAX(id) from heartbeat where monitor_id = ?)", [
            monitorID
        ]);
    }

    /**
     * Check if monitor is under maintenance
     * @param {number} monitorID ID of monitor to check
     * @returns {Promise<boolean>} Is the monitor under maintenance
     */
    static async isUnderMaintenance(monitorID) {
        const maintenanceIDList = await R.getCol(`
            SELECT maintenance_id FROM monitor_maintenance
            WHERE monitor_id = ?
        `, [ monitorID ]);

        for (const maintenanceID of maintenanceIDList) {
            const maintenance = await UptimeKumaServer.getInstance().getMaintenance(maintenanceID);
            if (maintenance && await maintenance.isUnderMaintenance()) {
                return true;
            }
        }

        const parent = await Monitor.getParent(monitorID);
        if (parent != null) {
            return await Monitor.isUnderMaintenance(parent.id);
        }

        return false;
    }

    /**
     * Make sure monitor interval is between bounds
     * @returns {void}
     * @throws Interval is outside of range
     */
    validate() {
        if (this.interval > MAX_INTERVAL_SECOND) {
            throw new Error(`Interval cannot be more than ${MAX_INTERVAL_SECOND} seconds`);
        }
        if (this.interval < MIN_INTERVAL_SECOND) {
            throw new Error(`Interval cannot be less than ${MIN_INTERVAL_SECOND} seconds`);
        }

        if (this.type === "ping") {
            // ping parameters validation
            if (this.packetSize && (this.packetSize < PING_PACKET_SIZE_MIN || this.packetSize > PING_PACKET_SIZE_MAX)) {
                throw new Error(`Packet size must be between ${PING_PACKET_SIZE_MIN} and ${PING_PACKET_SIZE_MAX} (default: ${PING_PACKET_SIZE_DEFAULT})`);
            }

            if (this.ping_per_request_timeout && (this.ping_per_request_timeout < PING_PER_REQUEST_TIMEOUT_MIN || this.ping_per_request_timeout > PING_PER_REQUEST_TIMEOUT_MAX)) {
                throw new Error(`Per-ping timeout must be between ${PING_PER_REQUEST_TIMEOUT_MIN} and ${PING_PER_REQUEST_TIMEOUT_MAX} seconds (default: ${PING_PER_REQUEST_TIMEOUT_DEFAULT})`);
            }

            if (this.ping_count && (this.ping_count < PING_COUNT_MIN || this.ping_count > PING_COUNT_MAX)) {
                throw new Error(`Echo requests count must be between ${PING_COUNT_MIN} and ${PING_COUNT_MAX} (default: ${PING_COUNT_DEFAULT})`);
            }

            if (this.timeout) {
                const pingGlobalTimeout = Math.round(Number(this.timeout));

                if (pingGlobalTimeout < this.ping_per_request_timeout || pingGlobalTimeout < PING_GLOBAL_TIMEOUT_MIN || pingGlobalTimeout > PING_GLOBAL_TIMEOUT_MAX) {
                    throw new Error(`Timeout must be between ${PING_GLOBAL_TIMEOUT_MIN} and ${PING_GLOBAL_TIMEOUT_MAX} seconds (default: ${PING_GLOBAL_TIMEOUT_DEFAULT})`);
                }

                this.timeout = pingGlobalTimeout;
            }
        }
    }

    /**
     * Gets monitor notification of multiple monitor
     * @param {Array} monitorIDs IDs of monitor to get
     * @returns {Promise<LooseObject<any>>} object
     */
    static async getMonitorNotification(monitorIDs) {
        return await R.getAll(`
            SELECT monitor_notification.monitor_id, monitor_notification.notification_id
            FROM monitor_notification
            WHERE monitor_notification.monitor_id IN (${monitorIDs.map((_) => "?").join(",")})
        `, monitorIDs);
    }

    /**
     * Gets monitor tags of multiple monitor
     * @param {Array} monitorIDs IDs of monitor to get
     * @returns {Promise<LooseObject<any>>} object
     */
    static async getMonitorTag(monitorIDs) {
        return await R.getAll(`
            SELECT monitor_tag.monitor_id, monitor_tag.tag_id, monitor_tag.value, tag.name, tag.color
            FROM monitor_tag
            JOIN tag ON monitor_tag.tag_id = tag.id
            WHERE monitor_tag.monitor_id IN (${monitorIDs.map((_) => "?").join(",")})
        `, monitorIDs);
    }

    /**
     * Gets monitor notification rules of multiple monitors
     * @param {Array} monitorIDs IDs of monitor to get
     * @returns {Promise<LooseObject<any>[]>} List of monitor notification rules
     */
    static async getMonitorNotificationRules(monitorIDs) {
        if (!monitorIDs || monitorIDs.length === 0) {
            return [];
        }
        
        // Get all rules for these monitors
        const rules = await R.getAll(`
            SELECT monitor_notification_rule.id, monitor_notification_rule.monitor_id, 
                   monitor_notification_rule.delay, monitor_notification_rule.active
            FROM monitor_notification_rule
            WHERE monitor_notification_rule.monitor_id IN (${monitorIDs.map((_) => "?").join(",")})
            ORDER BY monitor_notification_rule.monitor_id, monitor_notification_rule.delay
        `, monitorIDs);

        // Get all notification IDs for these rules
        const ruleIDs = rules.map(r => r.id);
        if (ruleIDs.length === 0) {
            return [];
        }

        const ruleNotifications = await R.getAll(`
            SELECT monitor_notification_rule_notification.monitor_notification_rule_id,
                   monitor_notification_rule_notification.notification_id
            FROM monitor_notification_rule_notification
            WHERE monitor_notification_rule_notification.monitor_notification_rule_id IN (${ruleIDs.map((_) => "?").join(",")})
        `, ruleIDs);

        // Build a map of rule_id -> notification_ids
        const ruleNotificationMap = new Map();
        ruleNotifications.forEach(rn => {
            if (!ruleNotificationMap.has(rn.monitor_notification_rule_id)) {
                ruleNotificationMap.set(rn.monitor_notification_rule_id, []);
            }
            ruleNotificationMap.get(rn.monitor_notification_rule_id).push(rn.notification_id);
        });

        // Combine rules with their notifications
        return rules.map(rule => ({
            monitor_id: rule.monitor_id,
            id: rule.id,
            delay: rule.delay,
            duration: rule.delay, // Support both delay and duration for compatibility
            active: rule.active,
            notificationIds: ruleNotificationMap.get(rule.id) || [],
            notificationIDList: (ruleNotificationMap.get(rule.id) || []).reduce((acc, id) => {
                acc[id] = true;
                return acc;
            }, {})
        }));
    }

    /**
     * prepare preloaded data for efficient access
     * @param {Array} monitorData IDs & active field of monitor to get
     * @returns {Promise<LooseObject<any>>} object
     */
    static async preparePreloadData(monitorData) {

        const notificationsMap = new Map();
        const tagsMap = new Map();
        const maintenanceStatusMap = new Map();
        const childrenIDsMap = new Map();
        const activeStatusMap = new Map();
        const forceInactiveMap = new Map();
        const pathsMap = new Map();
        const dependenciesMap = new Map();
        const notificationRulesMap = new Map();

        if (monitorData.length > 0) {
            const monitorIDs = monitorData.map(monitor => monitor.id);
            const notifications = await Monitor.getMonitorNotification(monitorIDs);
            const tags = await Monitor.getMonitorTag(monitorIDs);
            const notificationRules = await Monitor.getMonitorNotificationRules(monitorIDs);
            const maintenanceStatuses = await Promise.all(monitorData.map(monitor => Monitor.isUnderMaintenance(monitor.id)));
            const childrenIDs = await Promise.all(monitorData.map(monitor => Monitor.getAllChildrenIDs(monitor.id)));
            const activeStatuses = await Promise.all(monitorData.map(monitor => Monitor.isActive(monitor.id, monitor.active)));
            const forceInactiveStatuses = await Promise.all(monitorData.map(monitor => Monitor.isParentActive(monitor.id)));
            const paths = await Promise.all(monitorData.map(monitor => Monitor.getAllPath(monitor.id, monitor.name)));
            const dependencies = await Promise.all(monitorData.map(monitor => Monitor.getDependencies(monitor.id)));

            notifications.forEach(row => {
                if (!notificationsMap.has(row.monitor_id)) {
                    notificationsMap.set(row.monitor_id, {});
                }
                notificationsMap.get(row.monitor_id)[row.notification_id] = true;
            });

            tags.forEach(row => {
                if (!tagsMap.has(row.monitor_id)) {
                    tagsMap.set(row.monitor_id, []);
                }
                tagsMap.get(row.monitor_id).push({
                    tag_id: row.tag_id,
                    monitor_id: row.monitor_id,
                    value: row.value,
                    name: row.name,
                    color: row.color
                });
            });

            monitorData.forEach((monitor, index) => {
                maintenanceStatusMap.set(monitor.id, maintenanceStatuses[index]);
            });

            monitorData.forEach((monitor, index) => {
                childrenIDsMap.set(monitor.id, childrenIDs[index]);
            });

            monitorData.forEach((monitor, index) => {
                activeStatusMap.set(monitor.id, activeStatuses[index]);
            });

            monitorData.forEach((monitor, index) => {
                forceInactiveMap.set(monitor.id, !forceInactiveStatuses[index]);
            });

            monitorData.forEach((monitor, index) => {
                pathsMap.set(monitor.id, paths[index]);
            });

            monitorData.forEach((monitor, index) => {
                dependenciesMap.set(monitor.id, dependencies[index]);
            });

            // Build notification rules map
            notificationRules.forEach(rule => {
                if (!notificationRulesMap.has(rule.monitor_id)) {
                    notificationRulesMap.set(rule.monitor_id, []);
                }
                notificationRulesMap.get(rule.monitor_id).push(rule);
            });
        }

        return {
            notifications: notificationsMap,
            tags: tagsMap,
            maintenanceStatus: maintenanceStatusMap,
            childrenIDs: childrenIDsMap,
            activeStatus: activeStatusMap,
            forceInactive: forceInactiveMap,
            paths: pathsMap,
            dependencies: dependenciesMap,
            notificationRules: notificationRulesMap,
        };
    }

    /**
     * Gets Parent of the monitor
     * @param {number} monitorID ID of monitor to get
     * @returns {Promise<LooseObject<any>>} Parent
     */
    static async getParent(monitorID) {
        return await R.getRow(`
            SELECT parent.* FROM monitor parent
    		LEFT JOIN monitor child
    			ON child.parent = parent.id
            WHERE child.id = ?
        `, [
            monitorID,
        ]);
    }

    /**
     * Gets all Children of the monitor
     * @param {number} monitorID ID of monitor to get
     * @returns {Promise<LooseObject<any>[]>} Children
     */
    static async getChildren(monitorID) {
        return await R.getAll(`
            SELECT * FROM monitor
            WHERE parent = ?
        `, [
            monitorID,
        ]);
    }

    /**
     * Gets the full path
     * @param {number} monitorID ID of the monitor to get
     * @param {string} name of the monitor to get
     * @returns {Promise<string[]>} Full path (includes groups and the name) of the monitor
     */
    static async getAllPath(monitorID, name) {
        const path = [ name ];

        if (this.parent === null) {
            return path;
        }

        let parent = await Monitor.getParent(monitorID);
        while (parent !== null) {
            path.unshift(parent.name);
            parent = await Monitor.getParent(parent.id);
        }

        return path;
    }

    /**
     * Gets recursive all child ids
     * @param {number} monitorID ID of the monitor to get
     * @returns {Promise<Array>} IDs of all children
     */
    static async getAllChildrenIDs(monitorID) {
        const childs = await Monitor.getChildren(monitorID);

        if (childs === null) {
            return [];
        }

        let childrenIDs = [];

        for (const child of childs) {
            childrenIDs.push(child.id);
            childrenIDs = childrenIDs.concat(await Monitor.getAllChildrenIDs(child.id));
        }

        return childrenIDs;
    }

    /**
     * Unlinks all children of the group monitor
     * @param {number} groupID ID of group to remove children of
     * @returns {Promise<void>}
     */
    static async unlinkAllChildren(groupID) {
        return await R.exec("UPDATE `monitor` SET parent = ? WHERE parent = ? ", [
            null, groupID
        ]);
    }

    /**
     * Delete a monitor from the system
     * @param {number} monitorID ID of the monitor to delete
     * @param {number} userID ID of the user who owns the monitor
     * @returns {Promise<void>}
     */
    static async deleteMonitor(monitorID, userID) {
        const server = UptimeKumaServer.getInstance();

        // Stop the monitor if it's running
        if (monitorID in server.monitorList) {
            await server.monitorList[monitorID].stop();
            delete server.monitorList[monitorID];
        }

        // Delete from database
        await R.exec("DELETE FROM monitor WHERE id = ? AND user_id = ? ", [
            monitorID,
            userID,
        ]);
    }

    /**
     * Recursively delete a monitor and all its descendants
     * @param {number} monitorID ID of the monitor to delete
     * @param {number} userID ID of the user who owns the monitor
     * @returns {Promise<void>}
     */
    static async deleteMonitorRecursively(monitorID, userID) {
        // Check if this monitor is a group
        const monitor = await R.findOne("monitor", " id = ? AND user_id = ? ", [
            monitorID,
            userID,
        ]);

        if (monitor && monitor.type === "group") {
            // Get all children and delete them recursively
            const children = await Monitor.getChildren(monitorID);
            if (children && children.length > 0) {
                for (const child of children) {
                    await Monitor.deleteMonitorRecursively(child.id, userID);
                }
            }
        }

        // Delete the monitor itself
        await Monitor.deleteMonitor(monitorID, userID);
    }

    /**
     * Checks recursive if parent (ancestors) are active
     * @param {number} monitorID ID of the monitor to get
     * @returns {Promise<boolean>} Is the parent monitor active?
     */
    static async isParentActive(monitorID) {
        const parent = await Monitor.getParent(monitorID);

        if (parent === null) {
            return true;
        }

        const parentActive = await Monitor.isParentActive(parent.id);
        return parent.active && parentActive;
    }

    /**
     * Obtains a new Oidc Token
     * @returns {Promise<object>} OAuthProvider client
     */
    async makeOidcTokenClientCredentialsRequest() {
        log.debug("monitor", `[${this.name}] The oauth access-token undefined or expired. Requesting a new token`);
        const oAuthAccessToken = await getOidcTokenClientCredentials(this.oauth_token_url, this.oauth_client_id, this.oauth_client_secret, this.oauth_scopes, this.oauth_audience, this.oauth_auth_method);
        if (this.oauthAccessToken?.expires_at) {
            log.debug("monitor", `[${this.name}] Obtained oauth access-token. Expires at ${new Date(this.oauthAccessToken?.expires_at * 1000)}`);
        } else {
            log.debug("monitor", `[${this.name}] Obtained oauth access-token. Time until expiry was not provided`);
        }

        return oAuthAccessToken;
    }

    /**
     * Store TLS certificate information and check for expiry
     * @param {object} tlsInfo Information about the TLS connection
     * @returns {Promise<void>}
     */
    async handleTlsInfo(tlsInfo) {
        await this.updateTlsInfo(tlsInfo);
        this.prometheus?.update(null, tlsInfo);

        if (!this.getIgnoreTls() && this.isEnabledExpiryNotification()) {
            log.debug("monitor", `[${this.name}] call checkCertExpiryNotifications`);
            await this.checkCertExpiryNotifications(tlsInfo);
        }
    }

    /**
     * Get all monitors that this monitor depends on
     * @param {number} monitorID ID of monitor to get dependencies for
     * @returns {Promise<LooseObject<any>[]>} List of monitors this monitor depends on
     */
    static async getDependencies(monitorID) {
        return await R.getAll(`
            SELECT 
                md.id as dependency_id,
                md.relation_type,
                m.id,
                m.name,
                m.type,
                m.active,
                h.status,
                h.msg
            FROM monitor_dependency md
            JOIN monitor m ON md.depends_on_monitor_id = m.id
            LEFT JOIN (
                SELECT monitor_id, status, msg
                FROM heartbeat
                WHERE id IN (
                    SELECT MAX(id) FROM heartbeat GROUP BY monitor_id
                )
            ) h ON m.id = h.monitor_id
            WHERE md.monitor_id = ?
            ORDER BY m.name
        `, [ monitorID ]);
    }

    /**
     * Get all monitors that depend on this monitor
     * @param {number} monitorID ID of monitor to get dependents for
     * @returns {Promise<LooseObject<any>[]>} List of monitors that depend on this monitor
     */
    static async getDependents(monitorID) {
        return await R.getAll(`
            SELECT 
                md.id as dependency_id,
                md.relation_type,
                m.id,
                m.name,
                m.type,
                m.active,
                h.status,
                h.msg
            FROM monitor_dependency md
            JOIN monitor m ON md.monitor_id = m.id
            LEFT JOIN (
                SELECT monitor_id, status, msg
                FROM heartbeat
                WHERE id IN (
                    SELECT MAX(id) FROM heartbeat GROUP BY monitor_id
                )
            ) h ON m.id = h.monitor_id
            WHERE md.depends_on_monitor_id = ?
            ORDER BY m.name
        `, [ monitorID ]);
    }

    /**
     * Add a dependency relationship
     * @param {number} monitorID ID of monitor that depends on another
     * @param {number} dependsOnMonitorID ID of monitor being depended on
     * @param {string} relationType Type of dependency (hard/soft)
     * @returns {Promise<void>}
     */
    static async addDependency(monitorID, dependsOnMonitorID, relationType = "hard") {
        // Prevent self-dependency
        if (monitorID === dependsOnMonitorID) {
            throw new Error("A monitor cannot depend on itself");
        }

        // Check for circular dependency
        const wouldCreateCycle = await Monitor.wouldCreateCircularDependency(monitorID, dependsOnMonitorID);
        if (wouldCreateCycle) {
            throw new Error("This dependency would create a circular dependency");
        }

        // Check if dependency already exists
        const existing = await R.findOne("monitor_dependency", 
            "monitor_id = ? AND depends_on_monitor_id = ?", 
            [ monitorID, dependsOnMonitorID ]);
        
        if (existing) {
            // Update existing dependency
            existing.relation_type = relationType;
            await R.store(existing);
        } else {
            // Create new dependency
            const dependency = R.dispense("monitor_dependency");
            dependency.monitor_id = monitorID;
            dependency.depends_on_monitor_id = dependsOnMonitorID;
            dependency.relation_type = relationType;
            await R.store(dependency);
        }
    }

    /**
     * Remove a dependency relationship
     * @param {number} monitorID ID of monitor that depends on another
     * @param {number} dependsOnMonitorID ID of monitor being depended on
     * @returns {Promise<void>}
     */
    static async removeDependency(monitorID, dependsOnMonitorID) {
        await R.exec(
            "DELETE FROM monitor_dependency WHERE monitor_id = ? AND depends_on_monitor_id = ?",
            [ monitorID, dependsOnMonitorID ]
        );
    }

    /**
     * Remove all dependencies for a monitor
     * @param {number} monitorID ID of monitor to remove dependencies for
     * @returns {Promise<void>}
     */
    static async removeAllDependencies(monitorID) {
        await R.exec(
            "DELETE FROM monitor_dependency WHERE monitor_id = ? OR depends_on_monitor_id = ?",
            [ monitorID, monitorID ]
        );
    }

    /**
     * Check if adding a dependency would create a circular dependency
     * @param {number} monitorID ID of monitor that would depend on another
     * @param {number} dependsOnMonitorID ID of monitor being depended on
     * @returns {Promise<boolean>} True if it would create a cycle
     */
    static async wouldCreateCircularDependency(monitorID, dependsOnMonitorID) {
        // If the target monitor already depends on this monitor (directly or indirectly),
        // adding this dependency would create a cycle
        const visited = new Set();
        const toVisit = [ dependsOnMonitorID ];

        while (toVisit.length > 0) {
            const currentID = toVisit.shift();
            
            if (currentID === monitorID) {
                return true; // Found a path back to monitorID, cycle detected
            }

            if (visited.has(currentID)) {
                continue; // Already visited this node
            }

            visited.add(currentID);

            // Get all monitors that currentID depends on
            const dependencies = await R.getAll(
                "SELECT depends_on_monitor_id FROM monitor_dependency WHERE monitor_id = ?",
                [ currentID ]
            );

            for (const dep of dependencies) {
                toVisit.push(dep.depends_on_monitor_id);
            }
        }

        return false; // No cycle detected
    }

    /**
     * Get dependency status for a monitor (whether any dependencies are down)
     * This helps determine if a monitor is down due to its dependencies
     * @param {number} monitorID ID of monitor to check
     * @returns {Promise<LooseObject<any>>} Dependency status information
     */
    static async getDependencyStatus(monitorID) {
        const dependencies = await Monitor.getDependencies(monitorID);
        const downDependencies = dependencies.filter(dep => dep.status === DOWN || dep.status === PENDING);
        const allDependenciesUp = downDependencies.length === 0;

        return {
            hasDependencies: dependencies.length > 0,
            totalDependencies: dependencies.length,
            downDependencies: downDependencies.length,
            allDependenciesUp,
            dependencies: dependencies.map(dep => ({
                id: dep.id,
                name: dep.name,
                type: dep.type,
                status: dep.status,
                relationType: dep.relation_type,
                msg: dep.msg
            }))
        };
    }
}

module.exports = Monitor;
