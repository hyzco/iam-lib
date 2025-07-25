import { Request, Response, NextFunction } from 'express';

export interface IamHandlers {
  login: (req: Request, res: Response, next: NextFunction) => any;
  register: (req: Request, res: Response, next: NextFunction) => any;
  refreshToken: (req: Request, res: Response, next: NextFunction) => any;
  logout: (req: Request, res: Response, next: NextFunction) => any;
  me: (req: Request, res: Response, next: NextFunction) => any;
  verifyAccessToken: (req: Request, res: Response, next: NextFunction) => any;
  requireRole: (role: string | []) => (req: Request, res: Response, next: NextFunction) => any;
  issueServiceToken: (id: any) => any;
  issueServiceToken: (token: any, publicKey: any) => any
  profile: {
    getProfile: (req: any, res: any, next: any) => Promise<any>;
    updateProfile: (req: any, res: any, next: any) => Promise<any>;
    deleteProfile: (req: any, res: any, next: any) => Promise<any>;
    createProfile: (req: any, res: any, next: any) => Promise<any>;

  }
}