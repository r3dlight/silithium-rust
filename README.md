# Silithium

This repository contains a Rust implementation of the Silithium hybrid
signature scheme family.  

The available algorithms are:

| Algorithm | Variant | Reference |
|-----|----| --- |
|  [`silithium`](src/silithium.rs)  | Silithium44-P256<br> Silithium65-P384<br> Silithium87-P521    | [draft-devevey-00](https://www.ietf.org/archive/id/draft-devevey-cfrg-silithium-00.html)
|  [`edilithium`](src/edilithium.rs)|   Edilithium25519  | [DGR26](https://eprint.iacr.org/2025/2059)

For more information about the Silithium scheme family, see the 
[Bibliography](#bibliography) section.

THIS IMPLEMENTATION SHOULD NOT BE CONSIDERED AS PRODUCTION-READY.

## Bibliography

    @InProceedings{10.1007/978-3-032-22698-3_5,
        author="Devevey, Julien and Guerreau, Morgane and Roméas, Maxime",
        title="Compact, Efficient and Non-separable Hybrid Signatures",
        booktitle="Post-Quantum Cryptography",
        year="2026",
        publisher="Springer Nature Switzerland",
        address="Cham",
        pages="143--177",
        isbn="978-3-032-22698-3"
    }

    @techreport{devevey-cfrg-silithium-00,
        number =    {draft-devevey-cfrg-silithium-00},
        type =      {Internet-Draft},
        institution =   {Internet Engineering Task Force},
        publisher = {Internet Engineering Task Force},
        url =       {https://datatracker.ietf.org/doc/draft-devevey-cfrg-silithium/00/},
        author =    {Julien Devevey and Maxime Roméas and Morgane Guerreau},
        title =     {{Silithium - A Compact, Efficient and Non-separable Hybrid Signature}},
        year =      2026,
    }

## Acknowledgements

Thanks to [@yhql](https://github.com/yhql) for his contributions to this project.

## License

This project is licensed under the terms of the MIT license.
