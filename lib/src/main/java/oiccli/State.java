package oiccli;

import oiccli.exceptions.ExpiredToken;
import oiccli.exceptions.UnknownState;
import sun.swing.plaf.synth.DefaultSynthStyle;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class State {

    private String clientId;
    private Database db;
    private int lifetime;

    public State(String clientId, Database db, String dbName, int lifetime) {
        this.clientId = clientId;
        if (db == null) {
            if (StringUtil.isNotNullAndNotEmpty(dbName)) {
                this.db = shelve.open(dbName, true);
            } else {
                this.db = new Database();
            }
        } else {
            this.db = db;
        }
        this.lifetime = lifetime;
    }

    public State(String clientId, Database db, String dbName) {
        this(clientId, db, dbName, 600);
    }

    public String createState(final String receiver, Object request) {
        String state = StringUtil.generateRandomString(24);
        final long now = System.currentTimeMillis();
        Map<String, Object> info = new HashMap<String, Object>() {{
            put("clientId", clientId);
            put("as", receiver);
            put("iat", now);
        }};
        switch (state) {
            case "1":
                this.db.set1(info);
                break;
            case "2":
                this.db.set2(info);
                break;
            case "3":
                this.db.set3(info);
                break;
        }

        return state;
    }

    public Map<String, Map<String, Object>> updateTokenInfo(Map<String, Map<String, Object>> info, AuthorizationResponse authorizationResponse) {
        Map<String, Object> hMap = info.get("token");
        if (hMap == null) {
            hMap = new HashMap<>();
        }

        String token = authorizationResponse.getAccessToken();
        hMap.put("accessToken", token);
        Integer expiresAtInteger = authorizationResponse.getExpiresIn();
        int expiresAt;
        if (expiresAtInteger != null) {
            expiresAt = expiresAtInteger.intValue();
            hMap.put("exp", System.currentTimeMillis() + expiresAt);
            hMap.put("expiresIn", expiresAt);
        } else {
            hMap.put("exp", System.currentTimeMillis() + ((Long) hMap.get("expiresIn")).longValue());
        }

        hMap.put("tokenType", authorizationResponse.getTokenType());
        hMap.put("scope", authorizationResponse.getScope());

        info.put("token", hMap);

        return info;
    }

    public Map<String, Map<String, Object>> addMessageInfo(AuthorizationResponse authorizationResponse, String state) {
        if (state == null) {
            state = authorizationResponse.getState();
        }

        //_info = self[state]  what are all the available types so i can create a switch/case?

        info.put("code", authorizationResponse.getCode());
        this.updateTokenInfo(info, authorizationResponse);

        info.put("idToken", authorizationResponse.getIdToken());
        info.put("refreshToken", authorizationResponse.getRefreshToken());

        switch (state) {
            case "1":
                this.db.set1(info);
                break;
            case "2":
                this.db.set2(info);
                break;
            case "3":
                this.db.set3(info);
                break;
        }

        return info;
    }

    public Map<String, String> addInfo(String state, Map<String, String> args) {
        Map<String, String> info = this.get(state);
        info.update(args);

        switch (state) {
            case "1":
                this.db.set1(info);
                break;
            case "2":
                this.db.set2(info);
                break;
            case "3":
                this.db.set3(info);
                break;
        }

        return info;
    }

    public Map<String, Object> getTokenInfo(String state, long now) throws ExpiredToken {
        //_tinfo = self[state]['token']
        //_exp = _tinfo['exp']
        if (now == 0) {
            now = System.currentTimeMillis();
        }
        if (now > _exp) {
            throw new ExpiredToken("Passed best before");
        }
        return _tinfo;
    }

    public Map<String, Object> getTokenInfo(String state) throws ExpiredToken {
        return getTokenInfo(state, 0);
    }

    public Map<String, Object> getResponseArgs(String state, ABCMeta request, int now) throws ExpiredToken {
        Map<String, String> info = state.getState(state);
        Map<String, Object> responseArgs = new HashMap<>();
        for (String claim : request.c_param) {
            if (claim.equals("accessToken")) {
                Map<String, Object> tInfo = this.getTokenInfo(state, now);
                if (tInfo == null) {
                    continue;
                }
                responseArgs.put(claim, tInfo.get("accessToken"));
            } else {
                responseArgs.put(claim, info.get(claim));
            }
        }

        return responseArgs;
    }

    public DefaultSynthStyle.StateInfo addResponse(AuthorizationResponse authorizationResponse, String state) throws UnknownState {
        if(!StringUtil.isNotNullAndNotEmpty(state)) {
            state = authorizationResponse.getState();
        }

        DefaultSynthStyle.StateInfo stateInfo = this.getState(state);
        if(stateInfo == null) {
            throw new UnknownState(state);
        }

        stateInfo.setCode(authorizationResponse.getCode());
        this.updateTokenInfo(stateInfo, authorizationResponse);

        for(String claim : Arrays.asList("idToken", "refreshToken")) {
            stateInfo.setClaim(authorizationResponse.getClaim());
        }

        this.setState(stateInfo);

        return stateInfo;
    }

    public String getIdToken(String state) {
        return this.get(state).get("idToken");
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }
}
