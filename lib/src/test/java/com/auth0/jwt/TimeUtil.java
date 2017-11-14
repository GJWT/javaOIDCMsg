package com.auth0.jwt;

import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Random;

public class TimeUtil {

    static Date generateRandomExpDateInFuture() {
        Random rnd = new Random();
        return new Date(Math.abs(System.currentTimeMillis() + rnd.nextLong()));
    }

    static Date generateRandomIatDateInPast() {
        GregorianCalendar gc = new GregorianCalendar();
        int year = randBetween(1900, 2010);
        gc.set(gc.YEAR, year);
        int dayOfYear = randBetween(1, gc.getActualMaximum(gc.DAY_OF_YEAR));
        gc.set(gc.DAY_OF_YEAR, dayOfYear);

        return new Date(gc.getTimeInMillis());
    }

    static int randBetween(int start, int end) {
        return start + (int)Math.round(Math.random() * (end - start));
    }

}
