import { NextApiRequest, NextApiResponse } from 'next';
import prismadb from '@/lib/prismadb';
import { AuthOptions, getServerSession } from 'next-auth';

const serverAuth = async (req: NextApiRequest, res: NextApiResponse, authOptions: AuthOptions) => {
  const session = await getServerSession(req, res, authOptions);
  if (!session?.user?.email) {
    throw new Error('Not signed in');
  }

  const currentUser = await prismadb.user.findUnique({ where: { email: session.user.email } });
  if (!currentUser) {
    throw new Error('Not signed in');
  }
  delete currentUser.hashedPassword;

  return { currentUser };
};

export default serverAuth;
