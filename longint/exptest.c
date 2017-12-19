/*************************************************************
**         Europäisches Institut für Systemsicherheit        *
**   Praktikum "Kryptographie und Datensicherheitstechnik"   *
**                                                           *
** Versuch 6: Langzahlarithmetik und Diffie-Hellmann         *
**            Key Exchange                                   *
**                                                           *
**************************************************************
**
** exptest.c: Testprogramm für die Moduloexponentationsroutine
**/

#include <stdio.h>
#include <stdlib.h>

#include <praktikum.h>
#include <gmp.h>

#include "versuch.h"

/***********************************************************************/
/*                  Testdaten und Ergebnisse                           */
/***********************************************************************/
struct {
  const char *x,*y,*p,*z;
} TestData[] = {
 { "db98c8131c06e6c2a5b511ea1a9fe006ee9d115223d31452e7995648b73be3aa7bcdeb531ddcf809ddc556903305d35884b1f18fa6fba6201d70abe19f5662ff",
   "c371bd6db0bb5f41e65c3d177e7cce9878f59f7413883cfa8a16e51dba391ef6cd57d38ffe361e713a951046b752b29cfd31f2886e3260ac371e2001feb29949",
   "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8c8ecc0f2c709259e3c75b01b91bda2f0c337b3dc691dec04a1d51a5e40d180d",
   "435f46d0749a8419f5c55dde206881c08a27a0ac8f8ab83cde3fd4adb781e272f751ad6cb628036a2926aaba02be594adc95e3b908f5456a25ee2fd367889d30" },

 { "8eca89c397711a192e57358cdea981be5e7e6f71e64b9c5d8e604c737dbab2aadd5eaff9f525d033029ccee3306683520444e96393abc5e442904f8cadd702b7",
   "f5b6f90d036f8abe99450d9212bb2cf7050250c5fa51501d7aa0f1420156926f86efa669979a3064fb674d75aa7bcea197661d51b388ccace533852a64e5145e",
   "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff438eecc131015fd88bbd354de510d1c947b8c078f94832761937a7d039252c3",
   "07acb1093a089efc11535147af29d1ac29714545ebb578d052f1ad0451166b1308880601faad195493779f846f778d264f0432427cc2942bd1b78bce9dec73d2" },

 { "bd12318b81454a1742930ddaf10185b6729fcb7cbf88cd69fea456d5c083701fcd80069b1e155e0df0043ff170bfe1a7953841386101f151826127a5b6c60dd4",
   "be14866dab6bdc489e626cdc51619f2cd126efeae09bfa0f04e15a122b0321e91061d28698ddc05c794a9b4202ad36a4da56d5e1f4d6d950ad5ce333410218b2",
   "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff72e01f03c3853f4aed722c460fda9b960ec82e7d1a1c37d1ea05413e68e53492",
   "5d958a93c3734bcdededb95c54d4140122bcb001580aa59fcef137e7753fcdb0e8b13f15d01762ba2962a43840a39162e5fac1e69ee2c5e2a3c55746840e3516" },

 { "6d6e57f4ab5d79892d7676c76b35e8ffee06605e96e5186174f19abe406570c7750db21139371fe329b1bfbcb94b3bf381fee8359fa1d0775fdde39230b1c7a2",
   "58e73a253c1130425cdcc706235616ce8e4cae1d6cb46719ef9c610a7be5e1c66b14f1ef7c0bc770805cb48f489906a061c83615cff1b27e05549fb5d3ccb64a",
   "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff5996876f980f6621273d68df43f9f4579047830ddedf092b5b6acdfc3977298d",
   "e2fbb1f1a4308ac1cc544873faaa37cd82210f1b3aff6a44cd321f43b2a2fbe8953d5ae50f7fbc2aa187063ee8bde44cacf39d11156eb14ef2c5bba293adf25c" },

 { "c7905fe5470df79247a3b8d063e6c178d65db09c1236d04b526ab94d56c1c4d5cddb2ef27d308d5983a060b208ffbb89bcd370a2a018a33529bb1e5dd33b35c4",
   "d083b30c7d2fb438a939cc6fa7e4ed366c378f94dd7fe6e3a9bf831ba1875a95d050220df647fa78342ffee98fbdd189e6a61d80e034cc41e10f9786e2b05e11",
   "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff103adb8570df345178bc1748f5d91556eabbdd797d957279a3bd7fd47f481850",
   "cdfeeb4165cc881011ac2a809fa4a6814aa0c429ff22bac13936158e14a6d10d382e9423847965923f01f4501b316610db559b4e36af980980df341ad0244480" }
};


/***********************************************************************/
/*                 Sonstige Deklarationen                              */
/***********************************************************************/

int main(int argc, char **argv)
{
  mpz_t x;
  mpz_t y;
  mpz_t p;
  mpz_t r1;
  mpz_t r2;
  int i;
  
  mpz_init(x);
  mpz_init(y);
  mpz_init(p);
  mpz_init(r1);
  mpz_init(r2);

  for (i=0; i<TABSIZE(TestData); i++) {

    mpz_init_set_str(x, TestData[i].x, 16);
    mpz_init_set_str(y, TestData[i].y, 16);
    mpz_init_set_str(p, TestData[i].p, 16);
    mpz_init_set_str(r1, TestData[i].z, 16);

    doexp(x, y, r2, p);
    
    if (mpz_cmp(r1, r2)) {
      printf("Ergebnisse differieren bei Test %d:\n",i+1);
      printf("  x = %s\n", mpz_get_str(NULL, 16, x));
      printf("  y = %s\n", mpz_get_str(NULL, 16, y));
      printf("  p = %s\n", mpz_get_str(NULL, 16, p));
      printf(" r1 = %s\n", mpz_get_str(NULL, 16, r1));
      printf(" r2 = %s\n", mpz_get_str(NULL, 16, r2));
    }else {
      printf("Ergebnisse sind korrekt\n");}

  }
  
  mpz_clear(x);
  mpz_clear(y);
  mpz_clear(p);
  mpz_clear(r1);
  mpz_clear(r2);

  return 0;
}
