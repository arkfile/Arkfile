declare module '*/config/argon2id-params.json' {
  interface Argon2idParams {
    memoryCostKiB: number;
    timeCost: number;
    parallelism: number;
    keyLength: number;
    variant: string;
  }
  
  const params: Argon2idParams;
  export default params;
}
