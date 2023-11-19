use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{quote, TokenStreamExt};
use syn::{
    parse_macro_input, parse_quote, punctuated::Punctuated, DeriveInput, Expr, ExprArray, Field,
    LitStr, Token,
};

#[proc_macro_derive(Validate, attributes(va))]
pub fn derive_validate(inp: TokenStream) -> TokenStream {
    let di = parse_macro_input!(inp as DeriveInput);
    let id = di.ident.clone();
    let mut supplied = None;
    for att in di.attrs {
        if att.meta.path() == &parse_quote!(va) {
            supplied = Some(att.parse_args::<proc_macro2::TokenStream>().unwrap());
        }
    }
    let implexpr = if let Some(e) = supplied {
        e
    } else {
        parse_quote!(impl Validate for #id)
    };
    let mut fnbody = TokenStream2::new();

    let mut ftype = None;

    let mut list_len = 0;
    let mut list = None;
    match di.data {
        syn::Data::Struct(struc) => {
            let mut k = Punctuated::<Expr, Token![,]>::new();
            for (ind, fie) in struc.fields.iter().enumerate() {
                let fi = if let Some(na) = &fie.ident {
                    quote!(#na)
                } else {
                    quote!(#ind)
                };
                let li = quote!(self.#fi.validate()?;);
                fnbody.extend(li);
                let fid = fie.ident.as_ref().unwrap();
                let lit = LitStr::new(&fid.to_string(), fid.span());
                k.push(parse_quote![(&mut self.#fid, #lit)]);
            }
            list = Some(k);
            list_len = struc.fields.len();
            if struc.fields.len() > 0 {
                ftype = Some(struc.fields.iter().next().unwrap().ty.clone())
            }
        }
        _ => todo!(),
    }

    let li = if let Some(ft) = ftype {
        if let Some(arr) = list {
            quote!(
                // type Items<'k> = [(&'k mut #ft, &'static str); #list_len] where Self: 'k;
                // fn list<'k>(&'k mut self) ->  Option<Self::Items<'k>> {
                //     Some([#arr])
                // }
            )
        } else {
            unreachable!()
        }
    } else {
        quote!(
            // type Items<'k> = () where Self: 'k;
            // fn list<'k>(&'k mut self) -> Option<Self::Items<'k>> {
            //     None
            // }
        )
    };

    quote!(
        #implexpr {
            fn validate(&self) -> Result<()> {
                #fnbody
                Result::Ok(())
            }
            #li
        }
    )
    .into()
}

#[test]
fn test() {
    let ex: Expr = parse_quote!(&self.2);
}
