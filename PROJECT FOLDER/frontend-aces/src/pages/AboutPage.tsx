import React from "react";

export default function AboutPage() {
  return (
    <div style={{padding:"28px 24px", maxWidth:700, margin:"0 auto"}}>
      <div style={{background:"var(--s)",border:"1px solid var(--bd)",borderRadius:10,padding:24}}>
        <h2 style={{fontSize:13,textTransform:"uppercase",letterSpacing:".06em",color:"var(--mu)",marginBottom:14}}>
          &#127758; About NorthStar Capital
        </h2>
        <p style={{color:"var(--mu)",lineHeight:1.8}}>
          NorthStar Capital is a leading boutique investment management firm specialising in
          alternative assets and digital securities. Founded in 2008, we serve institutional
          and HNWI clients across 40 markets globally.
        </p>
        <div style={{marginTop:20,display:"flex",gap:10}}>
          <button style={{background:"var(--s)",border:"1px solid var(--bd)",color:"var(--mu)"}}
                  onClick={()=>alert("Annual_Report_2024.pdf (simulated download)")}>
            Annual Report 2024
          </button>
          <button style={{background:"var(--s)",border:"1px solid var(--bd)",color:"var(--mu)"}}
                  onClick={()=>alert("Investor_Overview.pdf (simulated download)")}>
            Investor Overview
          </button>
        </div>
      </div>
    </div>
  );
}
