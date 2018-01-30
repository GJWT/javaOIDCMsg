package oiccli.webfinger;

public class URINormalizer {

    public boolean hasScheme(String path) {
        if (path.contains("://")) {
            return true;
        } else {
            String authority = path.replace("/", "#")
                    .replace("?", "#").split("#")[0];

            String hostOrPort;
            if (authority.contains(":")) {
                hostOrPort = authority.split(":", 1)[1];
                if (hostOrPort.matches("^\\d+$")) {
                    return false;
                }
            } else {
                return false;
            }
        }

        return true;
    }

    public static boolean isAccountSchemeAssumed(String path) {
        String[] arr;
        if (path.contains("@")) {
            arr = path.split("@");
            String host = arr[arr.length - 1];
            return !(host.contains(":") || host.contains("/") || host.contains("?"));
        } else {
            return false;
        }
    }

    public String normalize(String path) {
        if (!this.hasScheme(path)) {
            if (this.isAccountSchemeAssumed(path)) {
                path = "acct:" + path;
            } else {
                path = "https://" + path;
            }
        }

        return path.split("#")[0];
    }
}
