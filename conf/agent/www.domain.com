groom {
    // active      = no
    // secret      = ""
    // concurrency = 20
    // remote      = "www.domain.com:443"
    // service     = "/.well-known/groom-agent"
    // insecure    = no
    // targets {
    //     active = [ default ]
    //     default {
    //         method = ""
    //         path   = ""
    //         host   = "target"
    //         target = "http(s)://..."
    //     }
    // }
}
