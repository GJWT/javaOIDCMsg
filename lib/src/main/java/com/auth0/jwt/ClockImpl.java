package com.auth0.jwt;

import com.auth0.jwt.interfaces.Clock;

import java.util.Date;

public final class ClockImpl implements Clock {

    public ClockImpl() {
    }

    @Override
    public Date getToday() {
        return new Date();
    }
}
