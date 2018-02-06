package com.auth0.jwt.oiccli;

import com.auth0.jwt.creators.Message;
import com.auth0.jwt.oiccli.exceptions.ExpiredToken;
import com.auth0.jwt.oiccli.exceptions.UnknownState;
import com.google.common.base.Strings;
import java.util.HashMap;
import java.util.Map;

public class State {

    private String clientId;
    private Database db;
    private String dbName;
    private int lifetime;
    private String tokenInfo;

    public State(String clientId, Database db, String dbName, int lifetime) {
        this.clientId = clientId;
        this.db = db;
        if(this.db == null) {
            if(!Strings.isNullOrEmpty(dbName)) {
                this.db = shelve.open(dbName, true);
            } else {
                this.db = new Database();
            }
        }
        this.lifetime = lifetime;
    }

    public String createState(String receiver, AuthorizationRequest request, String state) {
        if(Strings.isNullOrEmpty(state)) {
            state = StringUtil.generateRandomString(24);
        }

        long now = System.currentTimeMillis();

        StateInfo stateInfo = new StateInfo(this.clientId, receiver, now);
        stateInfo.update(request);

        //self[_state] = _state_info
        return state;
    }

    public StateInfo updateTokenInfo(StateInfo info, Message authorizationResponse) {
        Token token = info.getToken();
        if (token == null) {
            token = new Token();
        }

        String tokenString = authorizationResponse.getAccessToken();
        token.setAccessToken(tokenString);
        Integer expiresAtInteger = authorizationResponse.getExpiresIn();
        int expiresAt;
        if (expiresAtInteger != null) {
            expiresAt = expiresAtInteger.intValue();
            token.setExp(System.currentTimeMillis() + expiresAt);
            token.setExpiresIn(expiresAt);
        } else {
            token.setExp(System.currentTimeMillis() + ((Long) token.getExpiresIn()).longValue());
        }

        token.setTokenType(authorizationResponse.getTokenType());
        token.setScope(authorizationResponse.getScope());

        info.setToken(token);

        return info;
    }

    public StateInfo addResponse(Message authorizationResponse, String state) throws UnknownState {
        if (Strings.isNullOrEmpty(state)) {
            state = authorizationResponse.getState();
        }

        StateInfo stateInfo = this.getDB().getStateInfo(state);
        if (stateInfo == null) {
            throw new UnknownState(state);
        }

        if(authorizationResponse instanceof AuthorizationResponse) {
            stateInfo.setCode(authorizationResponse.getCode());
        }

        this.updateTokenInfo(stateInfo, authorizationResponse);

        stateInfo.setToken(authorizationResponse.getIdToken());
        stateInfo.setRefreshToken(authorizationResponse.getRefreshToken());

        //TODO: Updated the state database
        //self[state] = _state_info

        return stateInfo;
    }

    public StateInfo addInfo(String state, Map<String,Object> args) {
        StateInfo stateInfo = this.getDB().getStateInfo(state);
        stateInfo.update(args);

        //TODO: Updated the state database
        //self[state] = _state_info

        return stateInfo;
    }

    public Token getTokenInfo(String state, long now) throws ExpiredToken {
        StateInfo stateInfo = this.getDB().getStateInfo(state);
        Token token = null;
        long exp = 0;
        if(stateInfo != null) {
            token = stateInfo.getToken();
            if(token != null) {
                exp = token.getExp();
            }
        }

        if (now == 0) {
            now = System.currentTimeMillis();
        }
        if (now > exp) {
            throw new ExpiredToken("Passed best before");
        }
        return token;
    }

    public Token getTokenInfo(String state) throws ExpiredToken {
        return getTokenInfo(state, 0);
    }

    public Map<String, String> getNonceToState(String nonce) {
        return this.getDB().get("nonce" + nonce);
    }

    public Map<String, Object> getResponseArgs(String state, AccessTokenRequest request, int now) throws ExpiredToken, NoSuchFieldException, IllegalAccessException {
        StateInfo stateInfo = this.getDB().getStateInfo(state);
        Map<String, Object> responseArgs = new HashMap<>();
        for (String claim : request.getCParam().keySet()) {
            if (claim.equals("accessToken")) {
                Token tInfo = this.getTokenInfo(state, now);
                if (tInfo == null) {
                    continue;
                }
                responseArgs.put(claim, tInfo.getAccessToken());
            } else {
                responseArgs.put(claim, stateInfo.getClass().getField(claim).get(this));
            }
        }

        return responseArgs;
    }

    public Token getIdToken(String state) {
        return this.getDB().getStateInfo(state).getToken();
    }

    private Database getDB() {
        return db;
    }

    public State(String clientId, Database db, String dbName) {
        this(clientId, db, dbName, 600);
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }
}
