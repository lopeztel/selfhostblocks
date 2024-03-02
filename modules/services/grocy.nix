{ config, pkgs, lib, ... }:

let
  cfg = config.shb.grocy;

  contracts = pkgs.callPackage ../contracts {};

  fqdn = "${cfg.subdomain}.${cfg.domain}";
in
{
  options.shb.grocy = {
    enable = lib.mkEnableOption "selfhostblocks.grocy";

    subdomain = lib.mkOption {
      type = lib.types.str;
      description = "Subdomain under which grocy will be served.";
      example = "grocy";
    };

    domain = lib.mkOption {
      type = lib.types.str;
      description = "domain under which grocy will be served.";
      example = "mydomain.com";
    };

    dataDir = lib.mkOption {
      description = "Folder where Grocy will store all its data.";
      type = lib.types.str;
      default = "/var/lib/grocy";
    };

    webPort = lib.mkOption {
      type = lib.types.int;
      description = "Grocy web port";
      default = 8114;
    };

    currency = lib.mkOption {
      type = lib.types.str;
      description = "ISO 4217 code for the currency to display.";
      default = "USD";
      example = "NOK";
    };

    culture = lib.mkOption {
      type = lib.types.str;
      description = "Display language of the frontend. Must be one of one of `de`, `en`, `da`, `en_GB`, `es`, `fr`, `hu`, `it`, `nl`, `no`, `pl`, `pt_BR`, `ru`, `sk_SK`, `sv_SE`, `tr`";
      default = "en";
      example = "no";
    };

    #ssl = lib.mkOption {
    #  description = "Path to SSL files";
    #  type = lib.types.nullOr contracts.ssl.certs;
    #  default = null;
    #};

    extraServiceConfig = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      description = "Extra configuration given to the systemd service file.";
      default = {};
      example = lib.literalExpression ''
      {
        MemoryHigh = "512M";
        MemoryMax = "900M";
      }
      '';
    };

    #oidcProvider = lib.mkOption {
    #  type = lib.types.str;
    #  description = "OIDC provider name";
    #  default = "Authelia";
    #};

    #authEndpoint = lib.mkOption {
    #  type = lib.types.str;
    #  description = "OIDC endpoint for SSO";
    #  example = "https://authelia.example.com";
    #};

    #oidcClientID = lib.mkOption {
    #  type = lib.types.str;
    #  description = "Client ID for the OIDC endpoint";
    #  default = "grocy";
    #};

    #oidcAdminUserGroup = lib.mkOption {
    #  type = lib.types.str;
    #  description = "OIDC admin group";
    #  default = "grocy_admin";
    #};

    #oidcUserGroup = lib.mkOption {
    #  type = lib.types.str;
    #  description = "OIDC user group";
    #  default = "grocy_user";
    #};

    #ssoSecretFile = lib.mkOption {
    #  type = lib.types.path;
    #  description = "File containing the SSO shared secret.";
    #};

    logLevel = lib.mkOption {
      type = lib.types.nullOr (lib.types.enum ["critical" "error" "warning" "info" "debug"]);
      description = "Enable logging.";
      default = false;
      example = true;
    };
  };

  config = lib.mkIf cfg.enable (lib.mkMerge [{

    services.grocy = {
      enable = true;
      hostName = "${fqdn}:${builtins.toString cfg.webPort}";
      nginx.enableSSL = false;
      dataDir = "/var/lib/grocy";
      settings.currency = cfg.currency;
      settings.culture = cfg.culture;
    };

    #services.nginx.virtualHosts."${fqdn}" = {
    #  http2 = true;
    #  forceSSL = !(isNull cfg.ssl);
    #  sslCertificate = lib.mkIf (!(isNull cfg.ssl)) cfg.ssl.paths.cert;
    #  sslCertificateKey = lib.mkIf (!(isNull cfg.ssl)) cfg.ssl.paths.key;

    #  # https://github.com/advplyr/grocy#nginx-reverse-proxy
    #  extraConfig = ''
    #    set $grocy 127.0.0.1;
    #    location / {
    #         proxy_set_header X-Forwarded-For    $proxy_add_x_forwarded_for;
    #         proxy_set_header  X-Forwarded-Proto $scheme;
    #         proxy_set_header  Host              $host;
    #         proxy_set_header Upgrade            $http_upgrade;
    #         proxy_set_header Connection         "upgrade";

    #         proxy_http_version                  1.1;

    #         proxy_pass                          http://$grocy:${builtins.toString cfg.webPort};
    #         proxy_redirect                      http:// https://;
    #       }
    #  '';
    #};

    #shb.authelia.oidcClients = [
    #  {
    #    id = cfg.oidcClientID;
    #    description = "Audiobookshelf";
    #    secretFile = cfg.ssoSecretFile;
    #    public = "false";
    #    authorization_policy = "one_factor";
    #    redirect_uris = [ 
    #    "https://${cfg.subdomain}.${cfg.domain}/auth/openid/callback" 
    #    "https://${cfg.subdomain}.${cfg.domain}/auth/openid/mobile-redirect" 
    #    ];
    #  }
    #];
    #
    ## We want grocy to create files in the media group and to make those files group readable.
    #users.users.grocy = {
    #  extraGroups = [ "media" ];
    #};
    #systemd.services.grocyd.serviceConfig.Group = lib.mkForce "media";
    #systemd.services.grocyd.serviceConfig.UMask = lib.mkForce "0027";

    ## We backup the whole grocy directory and set permissions for the backup user accordingly.
    #users.groups.grocy.members = [ "backup" ];
    #users.groups.media.members = [ "backup" ];
    #shb.backup.instances.grocy = {
    #  sourceDirectories = [
    #    /var/lib/${config.services.grocy.dataDir}
    #  ];
    #};
  } {
    systemd.services.grocyd.serviceConfig = cfg.extraServiceConfig;
  }]);
}
