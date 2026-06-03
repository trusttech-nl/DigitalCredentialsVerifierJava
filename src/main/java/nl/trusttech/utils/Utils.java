package nl.trusttech.utils;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;
import java.math.BigInteger;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;
import java.util.TimeZone;

public class Utils {
    public static Date parseDate(String dateStr) throws Exception {
        if (dateStr == null) {
            throw new Exception("Date string is null");
        }

        try{
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
            sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
            return sdf.parse(dateStr);
        } catch (Exception e) {
            System.out.println("Input date string is not parsed by yyyy-MM-dd'T'HH:mm:ss'Z'");
        }


        try{
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.S'Z'");
            sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
            return sdf.parse(dateStr);
        } catch (Exception e) {
            System.out.println("Input date string is not parsed by yyyy-MM-dd'T'HH:mm:ss.S'Z'");
        }

        throw new Exception("No valid format found to parse date string:" + dateStr);
    }

    public static Map<String, Object> jsonToMap(String json) {
        Gson gson = new Gson();
        Type type = new TypeToken<Map<String, Object>>() {}.getType();
        return gson.fromJson(json, type);
    }

    public static byte[] toBytes32(BigInteger value) {
        byte[] raw = value.toByteArray();
        if (raw.length == 32) return raw;
        byte[] result = new byte[32];
        if (raw.length > 32) {
            System.arraycopy(raw, raw.length - 32, result, 0, 32);
        } else {
            System.arraycopy(raw, 0, result, 32 - raw.length, raw.length);
        }
        return result;
    }
}
